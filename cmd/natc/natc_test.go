// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tailcfg"
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

func TestRandV4(t *testing.T) {
	pfx := netip.MustParsePrefix("100.64.1.0/24")

	for i := 0; i < 512; i++ {
		ip := randV4(pfx)
		if !pfx.Contains(ip) {
			t.Errorf("randV4(%s) = %s; not contained in prefix", pfx, ip)
		}
	}
}

func TestDNSResponse(t *testing.T) {
	tests := []struct {
		name        string
		questions   []dnsmessage.Question
		addrs       []netip.Addr
		wantEmpty   bool
		wantAnswers []struct {
			name  string
			qType dnsmessage.Type
			addr  netip.Addr
		}
	}{
		{
			name:        "empty_request",
			questions:   []dnsmessage.Question{},
			addrs:       []netip.Addr{},
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
			addrs: []netip.Addr{netip.MustParseAddr("100.64.1.5")},
			wantAnswers: []struct {
				name  string
				qType dnsmessage.Type
				addr  netip.Addr
			}{
				{
					name:  "example.com.",
					qType: dnsmessage.TypeA,
					addr:  netip.MustParseAddr("100.64.1.5"),
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
			addrs: []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0:a99c:0001:0505:0505:0505")},
			wantAnswers: []struct {
				name  string
				qType dnsmessage.Type
				addr  netip.Addr
			}{
				{
					name:  "example.com.",
					qType: dnsmessage.TypeAAAA,
					addr:  netip.MustParseAddr("fd7a:115c:a1e0:a99c:0001:0505:0505:0505"),
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
			addrs:       []netip.Addr{},
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
			addrs:       []netip.Addr{},
			wantAnswers: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &dnsmessage.Message{
				Header: dnsmessage.Header{
					ID: 1234,
				},
				Questions: tc.questions,
			}

			resp, err := dnsResponse(req, tc.addrs)
			if err != nil {
				t.Fatalf("dnsResponse() error = %v", err)
			}

			if tc.wantEmpty && len(resp) != 0 {
				t.Errorf("dnsResponse() returned non-empty response when expected empty")
			}

			if !tc.wantEmpty && len(resp) == 0 {
				t.Errorf("dnsResponse() returned empty response when expected non-empty")
			}

			if len(resp) > 0 {
				var msg dnsmessage.Message
				err = msg.Unpack(resp)
				if err != nil {
					t.Fatalf("Failed to unpack response: %v", err)
				}

				if !msg.Header.Response {
					t.Errorf("Response header is not set")
				}

				if msg.Header.ID != req.Header.ID {
					t.Errorf("Response ID = %d, want %d", msg.Header.ID, req.Header.ID)
				}

				if len(tc.wantAnswers) > 0 {
					if len(msg.Answers) != len(tc.wantAnswers) {
						t.Errorf("got %d answers, want %d", len(msg.Answers), len(tc.wantAnswers))
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

							var gotIP netip.Addr
							switch want.qType {
							case dnsmessage.TypeA:
								if ans.Body.(*dnsmessage.AResource) == nil {
									t.Errorf("answer[%d] not an A record", i)
									continue
								}
								resource := ans.Body.(*dnsmessage.AResource)
								gotIP = netip.AddrFrom4([4]byte(resource.A))
							case dnsmessage.TypeAAAA:
								if ans.Body.(*dnsmessage.AAAAResource) == nil {
									t.Errorf("answer[%d] not an AAAA record", i)
									continue
								}
								resource := ans.Body.(*dnsmessage.AAAAResource)
								gotIP = netip.AddrFrom16([16]byte(resource.AAAA))
							}

							if gotIP != want.addr {
								t.Errorf("answer[%d] IP = %s, want %s", i, gotIP, want.addr)
							}
						}
					}
				}
			}
		})
	}
}

func TestPerPeerState(t *testing.T) {
	c := &connector{
		v4Ranges:      []netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")},
		v6ULA:         netip.MustParsePrefix("fd7a:115c:a1e0:a99c:0001::/80"),
		dnsAddr:       netip.MustParseAddr("100.64.1.0"),
		numV4DNSAddrs: (1<<(32-24) - 1),
	}

	ps := &perPeerState{c: c}

	addrs, err := ps.ipForDomain("example.com")
	if err != nil {
		t.Fatalf("ipForDomain() error = %v", err)
	}

	if len(addrs) != 2 {
		t.Fatalf("ipForDomain() returned %d addresses, want 2", len(addrs))
	}

	v4 := addrs[0]
	v6 := addrs[1]

	if !v4.Is4() {
		t.Errorf("First address is not IPv4: %s", v4)
	}

	if !v6.Is6() {
		t.Errorf("Second address is not IPv6: %s", v6)
	}

	if !c.v4Ranges[0].Contains(v4) {
		t.Errorf("IPv4 address %s not in range %s", v4, c.v4Ranges[0])
	}

	domain, ok := ps.domainForIP(v4)
	if !ok {
		t.Errorf("domainForIP(%s) not found", v4)
	} else if domain != "example.com" {
		t.Errorf("domainForIP(%s) = %s, want %s", v4, domain, "example.com")
	}

	domain, ok = ps.domainForIP(v6)
	if !ok {
		t.Errorf("domainForIP(%s) not found", v6)
	} else if domain != "example.com" {
		t.Errorf("domainForIP(%s) = %s, want %s", v6, domain, "example.com")
	}

	addrs2, err := ps.ipForDomain("example.com")
	if err != nil {
		t.Fatalf("ipForDomain() second call error = %v", err)
	}

	if !slices.Equal(addrs, addrs2) {
		t.Errorf("ipForDomain() second call = %v, want %v", addrs2, addrs)
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

func TestConnectorGenerateDNSResponse(t *testing.T) {
	c := &connector{
		v4Ranges:      []netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")},
		v6ULA:         netip.MustParsePrefix("fd7a:115c:a1e0:a99c:0001::/80"),
		dnsAddr:       netip.MustParseAddr("100.64.1.0"),
		numV4DNSAddrs: (1<<(32-24) - 1),
	}

	req := &dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1234},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("example.com."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	nodeID := tailcfg.NodeID(12345)

	resp1, err := c.generateDNSResponse(req, nodeID)
	if err != nil {
		t.Fatalf("generateDNSResponse() error = %v", err)
	}
	if len(resp1) == 0 {
		t.Fatalf("generateDNSResponse() returned empty response")
	}

	resp2, err := c.generateDNSResponse(req, nodeID)
	if err != nil {
		t.Fatalf("generateDNSResponse() second call error = %v", err)
	}

	if !cmp.Equal(resp1, resp2) {
		t.Errorf("generateDNSResponse() responses differ between calls")
	}
}

func TestIPPoolExhaustion(t *testing.T) {
	smallPrefix := netip.MustParsePrefix("100.64.1.0/30") // Only 4 IPs: .0, .1, .2, .3
	c := &connector{
		v6ULA:         netip.MustParsePrefix("fd7a:115c:a1e0:a99c:0001::/80"),
		v4Ranges:      []netip.Prefix{smallPrefix},
		dnsAddr:       netip.MustParseAddr("100.64.1.0"),
		numV4DNSAddrs: 3,
	}

	ps := &perPeerState{c: c}

	assignedIPs := make(map[netip.Addr]string)

	domains := []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"}

	var errs []error

	for i := 0; i < 5; i++ {
		for _, domain := range domains {
			addrs, err := ps.ipForDomain(domain)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to get IP for domain %q: %w", domain, err))
				continue
			}

			for _, addr := range addrs {
				if d, ok := assignedIPs[addr]; ok {
					if d != domain {
						t.Errorf("IP %s reused for domain %q, previously assigned to %q", addr, domain, d)
					}
				} else {
					assignedIPs[addr] = domain
				}
			}
		}
	}

	for addr, domain := range assignedIPs {
		if addr.Is4() && !smallPrefix.Contains(addr) {
			t.Errorf("IP %s for domain %q not in expected range %s", addr, domain, smallPrefix)
		}
		if addr.Is6() && !c.v6ULA.Contains(addr) {
			t.Errorf("IP %s for domain %q not in expected range %s", addr, domain, c.v6ULA)
		}
		if addr == c.dnsAddr {
			t.Errorf("IP %s for domain %q is the reserved DNS address", addr, domain)
		}
	}

	// expect one error for each iteration with the 4th domain
	if len(errs) != 5 {
		t.Errorf("Expected 5 errors, got %d: %v", len(errs), errs)
	}
	for _, err := range errs {
		if !errors.Is(err, ErrNoIPsAvailable) {
			t.Errorf("generateDNSResponse() error = %v, want ErrNoIPsAvailable", err)
		}
	}
}
