// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package androiddns

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tstest"
)

// startFakeDaemon starts a fake dnsproxyd on a unix socket and points
// the package at it. For each connection it parses the resnsend
// command, decodes the query, and replies with what answer returns.
// If answer returns a negative value, that value is sent as the
// initial big-endian result (the daemon's -errno case).
func startFakeDaemon(t *testing.T, answer func(query []byte) (ans []byte, errno int32)) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "dnsproxyd")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tstest.Replace(t, &socketPath, sock)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, maxCmdSize)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				cmd := string(buf[:n])
				nul := strings.IndexByte(cmd, 0)
				if nul < 0 {
					t.Error("command not NUL terminated in a single read")
					return
				}
				f := strings.Fields(cmd[:nul])
				if len(f) != 4 || f[0] != "resnsend" {
					t.Errorf("bad command %q", cmd[:nul])
					return
				}
				query, err := base64.StdEncoding.DecodeString(f[3])
				if err != nil {
					t.Errorf("bad base64 %q: %v", f[3], err)
					return
				}
				ans, errno := answer(query)
				var be [4]byte
				if errno < 0 {
					binary.BigEndian.PutUint32(be[:], uint32(errno))
					c.Write(be[:])
					return
				}
				binary.BigEndian.PutUint32(be[:], 0) // rcode
				c.Write(be[:])
				binary.BigEndian.PutUint32(be[:], uint32(len(ans)))
				c.Write(be[:])
				c.Write(ans)
			}()
		}
	}()
}

// dnsAnswer builds a wire-format answer to the single-question query,
// answering A questions with 1.2.3.4 and AAAA questions with ::6.
func dnsAnswer(t *testing.T, query []byte) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		t.Errorf("parsing query: %v", err)
		return nil
	}
	q, err := p.Question()
	if err != nil {
		t.Errorf("reading question: %v", err)
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:            hdr.ID,
		Response:      true,
		Authoritative: true,
	})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	rh := dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 60}
	switch q.Type {
	case dnsmessage.TypeA:
		rh.Type = dnsmessage.TypeA
		b.AResource(rh, dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}})
	case dnsmessage.TypeAAAA:
		rh.Type = dnsmessage.TypeAAAA
		b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: [16]byte{15: 6}})
	}
	ans, err := b.Finish()
	if err != nil {
		t.Errorf("building answer: %v", err)
		return nil
	}
	return ans
}

func makeQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	b.StartQuestions()
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestQuery(t *testing.T) {
	startFakeDaemon(t, func(query []byte) ([]byte, int32) {
		return dnsAnswer(t, query), 0
	})
	query := makeQuery(t, "example.com.", dnsmessage.TypeA)
	ans, err := Query(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(ans)
	if err != nil {
		t.Fatal(err)
	}
	if hdr.ID != 0x1234 {
		t.Errorf("answer ID = %#x; want %#x", hdr.ID, 0x1234)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AnswerHeader(); err != nil {
		t.Fatal(err)
	}
	a, err := p.AResource()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := netip.AddrFrom4(a.A), netip.AddrFrom4([4]byte{1, 2, 3, 4}); got != want {
		t.Errorf("answer = %v; want %v", got, want)
	}
}

func TestQueryDaemonError(t *testing.T) {
	startFakeDaemon(t, func(query []byte) ([]byte, int32) {
		return nil, -111 // -ECONNREFUSED
	})
	query := makeQuery(t, "example.com.", dnsmessage.TypeA)
	_, err := Query(context.Background(), query)
	if err == nil {
		t.Fatal("Query succeeded; want error")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error %q does not mention connection refused", err)
	}
}

func TestQueryTooLarge(t *testing.T) {
	_, err := Query(context.Background(), make([]byte, maxCmdSize))
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v; want too-large error", err)
	}
}

func TestQueryContextCancel(t *testing.T) {
	startFakeDaemon(t, func(query []byte) ([]byte, int32) {
		time.Sleep(5 * time.Second)
		return dnsAnswer(t, query), 0
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	query := makeQuery(t, "example.com.", dnsmessage.TypeA)
	if _, err := Query(ctx, query); err == nil {
		t.Fatal("Query succeeded; want timeout error")
	}
}

// TestResolver exercises the full net.Resolver integration: Go's
// built-in resolver framing queries over our conn and parsing the
// answers the fake daemon returns.
func TestResolver(t *testing.T) {
	startFakeDaemon(t, func(query []byte) ([]byte, int32) {
		return dnsAnswer(t, query), 0
	})
	r := NewResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	addrs, err := r.LookupNetIP(ctx, "ip", "example.com.")
	if err != nil {
		t.Fatal(err)
	}
	want4 := netip.MustParseAddr("1.2.3.4")
	want6 := netip.MustParseAddr("::6")
	if !slices.Contains(addrs, want4) || !slices.Contains(addrs, want6) {
		t.Errorf("LookupNetIP = %v; want both %v and %v", addrs, want4, want6)
	}
}
