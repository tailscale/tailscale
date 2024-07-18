// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package publicdns

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestInit(t *testing.T) {
	for _, baseKey := range KnownDoHPrefixes() {
		baseSet := DoHIPsOfBase(baseKey)
		for _, addr := range baseSet {
			back, only, ok := DoHEndpointFromIP(addr)
			if !ok {
				t.Errorf("DoHEndpointFromIP(%v) not mapped back to %v", addr, baseKey)
				continue
			}
			if only {
				t.Errorf("unexpected DoH only bit set for %v", addr)
			}
			if back != baseKey {
				t.Errorf("Expected %v to map to %s, got %s", addr, baseKey, back)
			}
		}
	}
}

func TestDoHV6(t *testing.T) {
	tests := []struct {
		in      string
		firstIP netip.Addr
		want    bool
	}{
		{"https://cloudflare-dns.com/dns-query", netip.MustParseAddr("2606:4700:4700::1111"), true},
		{"https://dns.google/dns-query", netip.MustParseAddr("2001:4860:4860::8888"), true},
		{"bogus", netip.Addr{}, false},
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			ip, ok := DoHV6(test.in)
			if ok != test.want || ip != test.firstIP {
				t.Errorf("DohV6 got (%v: IPv6 %v) for %v, want (%v: IPv6 %v)", ip, ok, test.in, test.firstIP, test.want)
			}
		})
	}
}

func TestDoHIPsOfBase(t *testing.T) {
	ips := func(s ...string) (ret []netip.Addr) {
		for _, ip := range s {
			ret = append(ret, netip.MustParseAddr(ip))
		}
		return
	}
	tests := []struct {
		base string
		want []netip.Addr
	}{
		{
			base: "https://cloudflare-dns.com/dns-query",
			want: ips("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"),
		},
		{
			base: "https://dns.nextdns.io/",
			want: ips(),
		},
		{
			base: "https://dns.nextdns.io/ff",
			want: ips(
				"45.90.28.0",
				"45.90.30.0",
				"2a07:a8c0::ff",
				"2a07:a8c1::ff",
			),
		},
		{
			base: "https://dns.nextdns.io/c3a884",
			want: ips(
				"45.90.28.0",
				"45.90.30.0",
				"2a07:a8c0::c3:a884",
				"2a07:a8c1::c3:a884",
			),
		},
		{
			base: "https://dns.nextdns.io/112233445566778899aabbcc",
			want: ips(
				"45.90.28.0",
				"45.90.30.0",
				"2a07:a8c0:1122:3344:5566:7788:99aa:bbcc",
				"2a07:a8c1:1122:3344:5566:7788:99aa:bbcc",
			),
		},
		{
			base: "https://dns.nextdns.io/112233445566778899aabbccdd",
			want: ips(), // nothing; profile length is over 12 bytes
		},
		{
			base: "https://dns.nextdns.io/c3a884/with/more/stuff",
			want: ips(
				"45.90.28.0",
				"45.90.30.0",
				"2a07:a8c0::c3:a884",
				"2a07:a8c1::c3:a884",
			),
		},
		{
			base: "https://dns.nextdns.io/c3a884?with=query&params",
			want: ips(
				"45.90.28.0",
				"45.90.30.0",
				"2a07:a8c0::c3:a884",
				"2a07:a8c1::c3:a884",
			),
		},
		{
			base: "https://dns.controld.com/hyq3ipr2ct",
			want: ips(
				"76.76.2.22",
				"76.76.10.22",
				"2606:1a40:0:6:7b5b:5949:35ad:0",
				"2606:1a40:1:6:7b5b:5949:35ad:0",
			),
		},
		{
			base: "https://dns.controld.com/112233445566778899aabbcc",
			want: ips(
				"76.76.2.22",
				"76.76.10.22",
				"2606:1a40:0:ffff:ffff:ffff:ffff:0",
				"2606:1a40:1:ffff:ffff:ffff:ffff:0",
			),
		},
		{
			base: "https://dns.controld.com/hyq3ipr2ct/test-host-name",
			want: ips(
				"76.76.2.22",
				"76.76.10.22",
				"2606:1a40:0:6:7b5b:5949:35ad:0",
				"2606:1a40:1:6:7b5b:5949:35ad:0",
			),
		},
	}
	for _, tt := range tests {
		got := DoHIPsOfBase(tt.base)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("DoHIPsOfBase(%q) = %v; want %v", tt.base, got, tt.want)
		}
	}
}
