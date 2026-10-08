// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package androiddns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tstest"
)

// startFakeLegacyDaemon starts a fake Android 9 era dnsproxyd that
// doesn't know resnsend and points the package at it. It answers
// resnsend with FrameworkListener's "500 Command not recognized" and
// serves getaddrinfo commands from lookup, which returns either
// addresses or a nonzero EAI_* code. The reply encoding is the one
// captured from a 32-bit Fire OS 7 (Android 9) device. It returns a
// counter of getaddrinfo commands served.
func startFakeLegacyDaemon(t *testing.T, lookup func(name string, family int) (addrs []netip.Addr, eai int32)) *atomic.Int32 {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "dnsproxyd")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tstest.Replace(t, &socketPath, sock)
	t.Cleanup(func() { noResNSend.Store(false) })

	var served atomic.Int32
	be32 := func(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
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
				if len(f) == 0 || f[0] != "getaddrinfo" {
					c.Write([]byte("500 Command not recognized\x00"))
					return
				}
				// getaddrinfo <name> <service> <flags> <family> <socktype> <protocol> <netId>
				if len(f) != 8 {
					t.Errorf("bad getaddrinfo command %q", cmd[:nul])
					c.Write([]byte("501 Invalid number of arguments to getaddrinfo\x00"))
					return
				}
				served.Add(1)
				family, err := strconv.Atoi(f[4])
				if err != nil {
					t.Errorf("bad family in %q", cmd[:nul])
					return
				}
				addrs, eai := lookup(f[1], family)
				if eai != 0 {
					c.Write([]byte("401\x00"))
					c.Write(be32(4))
					c.Write(binary.LittleEndian.AppendUint32(nil, uint32(eai)))
					return
				}
				c.Write([]byte("222\x00"))
				for _, a := range addrs {
					var sa []byte
					if a.Is4() {
						sa = append(binary.LittleEndian.AppendUint16(nil, afINET), 0, 0) // family, port
						sa = append(sa, a.AsSlice()...)
						sa = append(sa, make([]byte, 8)...) // sin_zero
					} else {
						sa = append(binary.LittleEndian.AppendUint16(nil, afINET6), 0, 0) // family, port
						sa = append(sa, 0, 0, 0, 0)                                       // flowinfo
						sa = append(sa, a.AsSlice()...)
						sa = append(sa, 0, 0, 0, 0) // scope_id
					}
					c.Write(be32(1)) // another addrinfo follows
					c.Write(be32(0)) // ai_flags
					if a.Is4() {
						c.Write(be32(afINET))
					} else {
						c.Write(be32(afINET6))
					}
					c.Write(be32(sockStream)) // ai_socktype
					c.Write(be32(6))          // ai_protocol (TCP)
					c.Write(be32(uint32(len(sa))))
					c.Write(sa)
					c.Write(be32(0)) // no canonical name
				}
				c.Write(be32(0))
			}()
		}
	}()
	return &served
}

// legacyLookup is a lookup function for startFakeLegacyDaemon that
// knows example.com (1.2.3.4 and ::6), v4only.example (10.0.0.1, no
// IPv6), and nothing else.
func legacyLookup(name string, family int) ([]netip.Addr, int32) {
	switch name {
	case "example.com":
		if family == afINET {
			return []netip.Addr{netip.MustParseAddr("1.2.3.4")}, 0
		}
		return []netip.Addr{netip.MustParseAddr("::6")}, 0
	case "v4only.example":
		if family == afINET {
			return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, 0
		}
		return nil, eaiNODATA
	}
	return nil, eaiNONAME
}

// parseAnswer returns the header and the A/AAAA addresses in a
// wire-format answer.
func parseAnswer(t *testing.T, ans []byte) (dnsmessage.Header, []netip.Addr) {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(ans)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	var addrs []netip.Addr
	for {
		rh, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if rh.TTL != 0 {
			t.Errorf("TTL = %d; want 0", rh.TTL)
		}
		switch rh.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				t.Fatal(err)
			}
			addrs = append(addrs, netip.AddrFrom4(a.A))
		case dnsmessage.TypeAAAA:
			a, err := p.AAAAResource()
			if err != nil {
				t.Fatal(err)
			}
			addrs = append(addrs, netip.AddrFrom16(a.AAAA))
		default:
			t.Fatalf("unexpected answer type %v", rh.Type)
		}
	}
	return hdr, addrs
}

func TestQueryLegacy(t *testing.T) {
	served := startFakeLegacyDaemon(t, legacyLookup)
	ctx := context.Background()

	ans, err := Query(ctx, makeQuery(t, "example.com.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if !noResNSend.Load() {
		t.Error("noResNSend not set after the daemon rejected resnsend")
	}
	hdr, addrs := parseAnswer(t, ans)
	if hdr.ID != 0x1234 || !hdr.Response || !hdr.RecursionAvailable || hdr.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("header = %+v", hdr)
	}
	if want := []netip.Addr{netip.MustParseAddr("1.2.3.4")}; !slices.Equal(addrs, want) {
		t.Errorf("A answer = %v; want %v", addrs, want)
	}

	ans, err = Query(ctx, makeQuery(t, "example.com.", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if _, addrs := parseAnswer(t, ans); !slices.Equal(addrs, []netip.Addr{netip.MustParseAddr("::6")}) {
		t.Errorf("AAAA answer = %v; want [::6]", addrs)
	}

	// EAI_NONAME is NXDOMAIN, so Go's resolver reports "no such host".
	ans, err = Query(ctx, makeQuery(t, "nope.example.", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if hdr, addrs := parseAnswer(t, ans); hdr.RCode != dnsmessage.RCodeNameError || len(addrs) != 0 {
		t.Errorf("NXDOMAIN answer: rcode %v, addrs %v", hdr.RCode, addrs)
	}

	// EAI_NODATA is a successful empty answer.
	ans, err = Query(ctx, makeQuery(t, "v4only.example.", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if hdr, addrs := parseAnswer(t, ans); hdr.RCode != dnsmessage.RCodeSuccess || len(addrs) != 0 {
		t.Errorf("NODATA answer: rcode %v, addrs %v", hdr.RCode, addrs)
	}

	// Only A and AAAA can be answered by getaddrinfo.
	if _, err := Query(ctx, makeQuery(t, "example.com.", dnsmessage.TypeTXT)); err == nil || !strings.Contains(err.Error(), "TypeTXT") {
		t.Errorf("TXT query error = %v; want unsupported type error", err)
	}

	if got := served.Load(); got != 4 {
		t.Errorf("daemon served %d getaddrinfo commands; want 4", got)
	}
}

func TestQueryLegacyOtherError(t *testing.T) {
	startFakeLegacyDaemon(t, func(name string, family int) ([]netip.Addr, int32) {
		return nil, 2 // EAI_AGAIN
	})
	_, err := Query(context.Background(), makeQuery(t, "example.com.", dnsmessage.TypeA))
	if err == nil || !strings.Contains(err.Error(), "EAI_AGAIN (2)") {
		t.Errorf("err = %v; want EAI_AGAIN error", err)
	}
}

// TestResolverLegacy exercises the full net.Resolver integration
// against the fake Android 9 daemon, including the resnsend probe
// that flips the package over to getaddrinfo.
func TestResolverLegacy(t *testing.T) {
	startFakeLegacyDaemon(t, legacyLookup)
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

	addrs, err = r.LookupNetIP(ctx, "ip", "v4only.example")
	if err != nil {
		t.Fatal(err)
	}
	if want := []netip.Addr{netip.MustParseAddr("10.0.0.1")}; !slices.Equal(addrs, want) {
		t.Errorf("LookupNetIP(v4only) = %v; want %v", addrs, want)
	}

	_, err = r.LookupNetIP(ctx, "ip", "nope.example")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Errorf("LookupNetIP(nope) error = %v; want IsNotFound DNSError", err)
	}

	_, err = r.LookupTXT(ctx, "example.com")
	if err == nil || !strings.Contains(err.Error(), "only answer A and AAAA") {
		t.Errorf("LookupTXT error = %v; want unsupported type error", err)
	}
}
