// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnscache

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tstest"
)

func TestMessageCache(t *testing.T) {
	clock := &tstest.Clock{
		Start: time.Date(1987, 11, 1, 0, 0, 0, 0, time.UTC),
	}
	mc := &MessageCache{Clock: clock.Now}
	mc.SetMaxCacheSize(2)
	clock.Advance(time.Second)

	var out bytes.Buffer
	if err := mc.ReplyFromCache(&out, makeQ(1, "foo.com.")); err != ErrCacheMiss {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := mc.AddCacheEntry(
		makeQ(2, "foo.com."),
		makeRes(2, "FOO.COM.", ttlOpt(10),
			&dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
			&dnsmessage.AResource{A: [4]byte{127, 0, 0, 2}})); err != nil {
		t.Fatal(err)
	}

	// Expect cache hit, with 10 seconds remaining.
	out.Reset()
	if err := mc.ReplyFromCache(&out, makeQ(3, "foo.com.")); err != nil {
		t.Fatalf("expected cache hit; got: %v", err)
	}
	if p := mustParseResponse(t, out.Bytes()); p.TxID != 3 {
		t.Errorf("TxID = %v; want %v", p.TxID, 3)
	} else if p.TTL != 10 {
		t.Errorf("TTL = %v; want 10", p.TTL)
	}

	// One second elapses, expect a cache hit, with 9 seconds
	// remaining.
	clock.Advance(time.Second)
	out.Reset()
	if err := mc.ReplyFromCache(&out, makeQ(4, "foo.com.")); err != nil {
		t.Fatalf("expected cache hit; got: %v", err)
	}
	if p := mustParseResponse(t, out.Bytes()); p.TxID != 4 {
		t.Errorf("TxID = %v; want %v", p.TxID, 4)
	} else if p.TTL != 9 {
		t.Errorf("TTL = %v; want 9", p.TTL)
	}

	// Expect cache miss on MX record.
	if err := mc.ReplyFromCache(&out, makeQ(4, "foo.com.", dnsmessage.TypeMX)); err != ErrCacheMiss {
		t.Fatalf("expected cache miss on MX; got: %v", err)
	}
	// Expect cache miss on CHAOS class.
	if err := mc.ReplyFromCache(&out, makeQ(4, "foo.com.", dnsmessage.ClassCHAOS)); err != ErrCacheMiss {
		t.Fatalf("expected cache miss on CHAOS; got: %v", err)
	}

	// Ten seconds elapses; expect a cache miss.
	clock.Advance(10 * time.Second)
	if err := mc.ReplyFromCache(&out, makeQ(5, "foo.com.")); err != ErrCacheMiss {
		t.Fatalf("expected cache miss, got: %v", err)
	}
}

type parsedMeta struct {
	TxID uint16
	TTL  uint32
}

func mustParseResponse(t testing.TB, r []byte) (ret parsedMeta) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(r)
	if err != nil {
		t.Fatal(err)
	}
	ret.TxID = h.ID
	qq, err := p.AllQuestions()
	if err != nil {
		t.Fatalf("AllQuestions: %v", err)
	}
	if len(qq) != 1 {
		t.Fatalf("num questions = %v; want 1", len(qq))
	}
	aa, err := p.AllAnswers()
	if err != nil {
		t.Fatalf("AllAnswers: %v", err)
	}
	for _, r := range aa {
		if ret.TTL == 0 {
			ret.TTL = r.Header.TTL
		}
		if ret.TTL != r.Header.TTL {
			t.Fatal("mixed TTLs")
		}
	}
	return ret
}

type responseOpt bool

type ttlOpt uint32

func makeQ(txID uint16, name string, opt ...any) []byte {
	opt = append(opt, responseOpt(false))
	return makeDNSPkt(txID, name, opt...)
}

func makeRes(txID uint16, name string, opt ...any) []byte {
	opt = append(opt, responseOpt(true))
	return makeDNSPkt(txID, name, opt...)
}

func makeDNSPkt(txID uint16, name string, opt ...any) []byte {
	typ := dnsmessage.TypeA
	class := dnsmessage.ClassINET
	var response bool
	var answers []dnsmessage.ResourceBody
	var ttl uint32 = 1 // one second by default
	for _, o := range opt {
		switch o := o.(type) {
		case dnsmessage.Type:
			typ = o
		case dnsmessage.Class:
			class = o
		case responseOpt:
			response = bool(o)
		case dnsmessage.ResourceBody:
			answers = append(answers, o)
		case ttlOpt:
			ttl = uint32(o)
		default:
			panic(fmt.Sprintf("unknown opt type %T", o))
		}
	}
	qname := dnsmessage.MustNewName(name)
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: txID, Response: response},
		Questions: []dnsmessage.Question{
			{
				Name:  qname,
				Type:  typ,
				Class: class,
			},
		},
	}
	for _, rb := range answers {
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  qname,
				Type:  typ,
				Class: class,
				TTL:   ttl,
			},
			Body: rb,
		})
	}
	buf, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return buf
}

func TestASCIILowerName(t *testing.T) {
	n := asciiLowerName(dnsmessage.MustNewName("Foo.COM."))
	if got, want := n.String(), "foo.com."; got != want {
		t.Errorf("got = %q; want %q", got, want)
	}
}

func TestGetDNSQueryCacheKey(t *testing.T) {
	tests := []struct {
		name  string
		pkt   []byte
		want  msgQ
		txID  uint16
		anyTX bool
	}{
		{
			name: "empty",
		},
		{
			name: "a",
			pkt:  makeQ(123, "foo.com."),
			want: msgQ{"foo.com.", dnsmessage.TypeA},
			txID: 123,
		},
		{
			name: "aaaa",
			pkt:  makeQ(6, "foo.com.", dnsmessage.TypeAAAA),
			want: msgQ{"foo.com.", dnsmessage.TypeAAAA},
			txID: 6,
		},
		{
			name: "normalize_case",
			pkt:  makeQ(123, "FoO.CoM."),
			want: msgQ{"foo.com.", dnsmessage.TypeA},
			txID: 123,
		},
		{
			name: "ignore_response",
			pkt:  makeRes(123, "foo.com."),
		},
		{
			name: "ignore_question_with_answers",
			pkt:  makeQ(2, "foo.com.", &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}),
		},
		{
			name:  "whatever_go_generates", // in case Go's net package grows functionality we don't handle
			pkt:   getGoNetPacketDNSQuery("from-go.foo."),
			want:  msgQ{"from-go.foo.", dnsmessage.TypeA},
			anyTX: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotTX, ok := getDNSQueryCacheKey(tt.pkt)
			if !ok {
				if tt.txID == 0 && got == (msgQ{}) {
					return
				}
				t.Fatal("failed")
			}
			if got != tt.want {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
			if gotTX != tt.txID && !tt.anyTX {
				t.Errorf("got tx %v, want %v", gotTX, tt.txID)
			}
		})
	}
}

func getGoNetPacketDNSQuery(name string) []byte {
	if runtime.GOOS == "windows" {
		// On Windows, Go's net.Resolver doesn't use the DNS client.
		// See https://github.com/golang/go/issues/33097 which
		// was approved but not yet implemented.
		// For now just pretend it's implemented to make this test
		// pass on Windows with complicated the caller.
		return makeQ(123, name)
	}
	res := make(chan []byte, 1)
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return goResolverConn(res), nil
		},
	}
	r.LookupIP(context.Background(), "ip4", name)
	return <-res
}

type goResolverConn chan<- []byte

func (goResolverConn) Close() error                       { return nil }
func (goResolverConn) LocalAddr() net.Addr                { return todoAddr{} }
func (goResolverConn) RemoteAddr() net.Addr               { return todoAddr{} }
func (goResolverConn) SetDeadline(t time.Time) error      { return nil }
func (goResolverConn) SetReadDeadline(t time.Time) error  { return nil }
func (goResolverConn) SetWriteDeadline(t time.Time) error { return nil }
func (goResolverConn) Read([]byte) (int, error)           { return 0, errors.New("boom") }
func (c goResolverConn) Write(p []byte) (int, error) {
	select {
	case c <- p[2:]: // skip 2 byte length for TCP mode DNS query
	default:
	}
	return 0, errors.New("boom")
}

type todoAddr struct{}

func (todoAddr) Network() string { return "unused" }
func (todoAddr) String() string  { return "unused-todoAddr" }
