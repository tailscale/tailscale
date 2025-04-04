// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net/netip"
	"testing"

	"github.com/gaissmai/bart"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/cmd/natc/ippool"
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
	v6ULA := netip.MustParsePrefix("fd7a:115c:a1e0:a99c:0001::/80")
	routes, dnsAddr, addrPool := calculateAddresses([]netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")})
	c := &connector{
		v6ULA:   v6ULA,
		ipPool:  &ippool.IPPool{V6ULA: v6ULA, IPSet: addrPool},
		routes:  routes,
		dnsAddr: dnsAddr,
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

	var msg dnsmessage.Message
	err = msg.Unpack(resp1)
	if err != nil {
		t.Fatalf("dnsmessage Unpack error = %v", err)
	}
	if len(msg.Answers) != 1 {
		t.Fatalf("expected 1 answer, got: %d", len(msg.Answers))
	}
}
