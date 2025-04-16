// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/cmd/natc/ippool"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
)

func prefixEqual(a, b netip.Prefix) bool {
	return a.Bits() == b.Bits() && a.Addr() == b.Addr()
}

func TestULA(t *testing.T) {
	tests := []struct {
		name     string
		siteID   uint16
		expected string
	}{
		{"zero", 0, "fd7a:115c:a1e0:a99c:0000::/80"},
		{"one", 1, "fd7a:115c:a1e0:a99c:0001::/80"},
		{"max", 65535, "fd7a:115c:a1e0:a99c:ffff::/80"},
		{"random", 12345, "fd7a:115c:a1e0:a99c:3039::/80"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ula(tc.siteID)
			expected := netip.MustParsePrefix(tc.expected)
			if !prefixEqual(got, expected) {
				t.Errorf("ula(%d) = %s; want %s", tc.siteID, got, expected)
			}
		})
	}
}

type recordingPacketConn struct {
	writes [][]byte
}

func (w *recordingPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	w.writes = append(w.writes, b)
	return len(b), nil
}

func (w *recordingPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

func (w *recordingPacketConn) Close() error {
	return nil
}

func (w *recordingPacketConn) LocalAddr() net.Addr {
	return nil
}

func (w *recordingPacketConn) RemoteAddr() net.Addr {
	return nil
}

func (w *recordingPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (w *recordingPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (w *recordingPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type resolver struct {
	resolves map[string][]netip.Addr
	fails    map[string]bool
}

func (r *resolver) LookupNetIP(ctx context.Context, _net, host string) ([]netip.Addr, error) {
	if addrs, ok := r.resolves[host]; ok {
		return addrs, nil
	}
	if _, ok := r.fails[host]; ok {
		return nil, &net.DNSError{IsTimeout: false, IsNotFound: false, Name: host, IsTemporary: true}
	}
	return nil, &net.DNSError{IsNotFound: true, Name: host}
}

type whois struct {
	peers map[string]*apitype.WhoIsResponse
}

func (w *whois) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	addr := netip.MustParseAddrPort(remoteAddr).Addr().String()
	if peer, ok := w.peers[addr]; ok {
		return peer, nil
	}
	return nil, fmt.Errorf("peer not found")
}

func TestDNSResponse(t *testing.T) {
	tests := []struct {
		name        string
		questions   []dnsmessage.Question
		wantEmpty   bool
		wantAnswers []struct {
			name  string
			qType dnsmessage.Type
			addr  netip.Addr
		}
		wantNXDOMAIN bool
		wantIgnored  bool
	}{
		{
			name:        "empty_request",
			questions:   []dnsmessage.Question{},
			wantEmpty:   false,
			wantAnswers: nil,
		},
		{
			name: "a_record",
			questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
			wantAnswers: []struct {
				name  string
				qType dnsmessage.Type
				addr  netip.Addr
			}{
				{
					name:  "example.com.",
					qType: dnsmessage.TypeA,
					addr:  netip.MustParseAddr("100.64.0.0"),
				},
			},
		},
		{
			name: "aaaa_record",
			questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				},
			},
			wantAnswers: []struct {
				name  string
				qType dnsmessage.Type
				addr  netip.Addr
			}{
				{
					name:  "example.com.",
					qType: dnsmessage.TypeAAAA,
					addr:  netip.MustParseAddr("fd7a:115c:a1e0::"),
				},
			},
		},
		{
			name: "soa_record",
			questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeSOA,
					Class: dnsmessage.ClassINET,
				},
			},
			wantAnswers: nil,
		},
		{
			name: "ns_record",
			questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeNS,
					Class: dnsmessage.ClassINET,
				},
			},
			wantAnswers: nil,
		},
		{
			name: "nxdomain",
			questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("noexist.example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
			wantNXDOMAIN: true,
		},
		{
			name: "servfail",
			questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("fail.example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
			wantEmpty: true, // TODO: pass through instead?
		},
		{
			name: "ignored",
			questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName("ignore.example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
			wantAnswers: []struct {
				name  string
				qType dnsmessage.Type
				addr  netip.Addr
			}{
				{
					name:  "ignore.example.com.",
					qType: dnsmessage.TypeA,
					addr:  netip.MustParseAddr("8.8.4.4"),
				},
			},
			wantIgnored: true,
		},
	}

	var rpc recordingPacketConn
	remoteAddr := must.Get(net.ResolveUDPAddr("udp", "100.64.254.1:12345"))

	routes, dnsAddr, addrPool := calculateAddresses([]netip.Prefix{netip.MustParsePrefix("10.64.0.0/24")})
	v6ULA := ula(1)
	c := connector{
		resolver: &resolver{
			resolves: map[string][]netip.Addr{
				"example.com.": {
					netip.MustParseAddr("8.8.8.8"),
					netip.MustParseAddr("2001:4860:4860::8888"),
				},
				"ignore.example.com.": {
					netip.MustParseAddr("8.8.4.4"),
				},
			},
			fails: map[string]bool{
				"fail.example.com.": true,
			},
		},
		whois: &whois{
			peers: map[string]*apitype.WhoIsResponse{
				"100.64.254.1": {
					Node: &tailcfg.Node{ID: 123},
				},
			},
		},
		ignoreDsts: &bart.Table[bool]{},
		routes:     routes,
		v6ULA:      v6ULA,
		ipPool:     &ippool.IPPool{IPSet: addrPool},
		dnsAddr:    dnsAddr,
	}
	c.ignoreDsts.Insert(netip.MustParsePrefix("8.8.4.4/32"), true)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rb := dnsmessage.NewBuilder(nil,
				dnsmessage.Header{
					ID: 1234,
				},
			)
			must.Do(rb.StartQuestions())
			for _, q := range tc.questions {
				rb.Question(q)
			}

			c.handleDNS(&rpc, must.Get(rb.Finish()), remoteAddr)

			writes := rpc.writes
			rpc.writes = rpc.writes[:0]

			if tc.wantEmpty {
				if len(writes) != 0 {
					t.Errorf("handleDNS() returned non-empty response when expected empty")
				}
				return
			}

			if !tc.wantEmpty && len(writes) != 1 {
				t.Fatalf("handleDNS() returned an unexpected number of responses: %d, want 1", len(writes))
			}

			resp := writes[0]
			var msg dnsmessage.Message
			err := msg.Unpack(resp)
			if err != nil {
				t.Fatalf("Failed to unpack response: %v", err)
			}

			if !msg.Header.Response {
				t.Errorf("Response header is not set")
			}

			if msg.Header.ID != 1234 {
				t.Errorf("Response ID = %d, want %d", msg.Header.ID, 1234)
			}

			if len(tc.wantAnswers) > 0 {
				if len(msg.Answers) != len(tc.wantAnswers) {
					t.Errorf("got %d answers, want %d:\n%s", len(msg.Answers), len(tc.wantAnswers), msg.GoString())
				} else {
					for i, want := range tc.wantAnswers {
						ans := msg.Answers[i]

						gotName := ans.Header.Name.String()
						if gotName != want.name {
							t.Errorf("answer[%d] name = %s, want %s", i, gotName, want.name)
						}

						if ans.Header.Type != want.qType {
							t.Errorf("answer[%d] type = %v, want %v", i, ans.Header.Type, want.qType)
						}

						switch want.qType {
						case dnsmessage.TypeA:
							if ans.Body.(*dnsmessage.AResource) == nil {
								t.Errorf("answer[%d] not an A record", i)
								continue
							}
						case dnsmessage.TypeAAAA:
							if ans.Body.(*dnsmessage.AAAAResource) == nil {
								t.Errorf("answer[%d] not an AAAA record", i)
								continue
							}
						}

						var gotIP netip.Addr
						switch want.qType {
						case dnsmessage.TypeA:
							resource := ans.Body.(*dnsmessage.AResource)
							gotIP = netip.AddrFrom4([4]byte(resource.A))
						case dnsmessage.TypeAAAA:
							resource := ans.Body.(*dnsmessage.AAAAResource)
							gotIP = netip.AddrFrom16([16]byte(resource.AAAA))
						}

						var wantIP netip.Addr
						if tc.wantIgnored {
							var net string
							var fxSelectIP func(netip.Addr) bool
							switch want.qType {
							case dnsmessage.TypeA:
								net = "ip4"
								fxSelectIP = func(a netip.Addr) bool {
									return a.Is4()
								}
							case dnsmessage.TypeAAAA:
								//TODO(fran) is this branch exercised?
								net = "ip6"
								fxSelectIP = func(a netip.Addr) bool {
									return a.Is6()
								}
							}
							ips := must.Get(c.resolver.LookupNetIP(t.Context(), net, want.name))
							for _, ip := range ips {
								if fxSelectIP(ip) {
									wantIP = ip
									break
								}
							}
						} else {
							addr := must.Get(c.ipPool.IPForDomain(tailcfg.NodeID(123), want.name))
							switch want.qType {
							case dnsmessage.TypeA:
								wantIP = addr
							case dnsmessage.TypeAAAA:
								wantIP = v6ForV4(v6ULA.Addr(), addr)
							}
						}
						if gotIP != wantIP {
							t.Errorf("answer[%d] IP = %s, want %s", i, gotIP, wantIP)
						}
					}
				}
			}

			if tc.wantNXDOMAIN {
				if msg.RCode != dnsmessage.RCodeNameError {
					t.Errorf("expected NXDOMAIN, got %v", msg.RCode)
				}
				if len(msg.Answers) != 0 {
					t.Errorf("expected no answers, got %d", len(msg.Answers))
				}
			}
		})
	}
}

func TestIgnoreDestination(t *testing.T) {
	ignoreDstTable := &bart.Table[bool]{}
	ignoreDstTable.Insert(netip.MustParsePrefix("192.168.1.0/24"), true)
	ignoreDstTable.Insert(netip.MustParsePrefix("10.0.0.0/8"), true)

	c := &connector{
		ignoreDsts: ignoreDstTable,
	}

	tests := []struct {
		name     string
		addrs    []netip.Addr
		expected bool
	}{
		{
			name:     "no_match",
			addrs:    []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")},
			expected: false,
		},
		{
			name:     "one_match",
			addrs:    []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("192.168.1.5")},
			expected: true,
		},
		{
			name:     "all_match",
			addrs:    []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.168.1.5")},
			expected: true,
		},
		{
			name:     "empty_addrs",
			addrs:    []netip.Addr{},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := c.ignoreDestination(tc.addrs)
			if got != tc.expected {
				t.Errorf("ignoreDestination(%v) = %v, want %v", tc.addrs, got, tc.expected)
			}
		})
	}
}

func TestV6V4(t *testing.T) {
	v6ULA := ula(1)

	tests := [][]string{
		{"100.64.0.0", "fd7a:115c:a1e0:a99c:1:0:6440:0"},
		{"0.0.0.0", "fd7a:115c:a1e0:a99c:1::"},
		{"255.255.255.255", "fd7a:115c:a1e0:a99c:1:0:ffff:ffff"},
	}

	for i, test := range tests {
		// to v6
		v6 := v6ForV4(v6ULA.Addr(), netip.MustParseAddr(test[0]))
		want := netip.MustParseAddr(test[1])
		if v6 != want {
			t.Fatalf("test %d: want: %v, got: %v", i, want, v6)
		}

		// to v4
		v4 := v4ForV6(netip.MustParseAddr(test[1]))
		want = netip.MustParseAddr(test[0])
		if v4 != want {
			t.Fatalf("test %d: want: %v, got: %v", i, want, v4)
		}
	}
}
