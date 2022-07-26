// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsaddr

import (
	"net/netip"
	"testing"

	"tailscale.com/net/netaddr"
)

func TestInCrostiniRange(t *testing.T) {
	tests := []struct {
		ip   netaddr.IP
		want bool
	}{
		{netaddr.IPv4(192, 168, 0, 1), false},
		{netaddr.IPv4(100, 101, 102, 103), false},
		{netaddr.IPv4(100, 115, 92, 0), true},
		{netaddr.IPv4(100, 115, 92, 5), true},
		{netaddr.IPv4(100, 115, 92, 255), true},
		{netaddr.IPv4(100, 115, 93, 40), true},
		{netaddr.IPv4(100, 115, 94, 1), false},
	}

	for _, test := range tests {
		if got := ChromeOSVMRange().Contains(test.ip); got != test.want {
			t.Errorf("inCrostiniRange(%q) = %v, want %v", test.ip, got, test.want)
		}
	}
}

func TestTailscaleServiceIPv6(t *testing.T) {
	got := TailscaleServiceIPv6().String()
	want := "fd7a:115c:a1e0::53"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestChromeOSVMRange(t *testing.T) {
	if got, want := ChromeOSVMRange().String(), "100.115.92.0/23"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestCGNATRange(t *testing.T) {
	if got, want := CGNATRange().String(), "100.64.0.0/10"; got != want {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestNewContainsIPFunc(t *testing.T) {
	f := NewContainsIPFunc([]netaddr.IPPrefix{netip.MustParsePrefix("10.0.0.0/8")})
	if f(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("bad")
	}
	if !f(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("bad")
	}
	f = NewContainsIPFunc([]netaddr.IPPrefix{netip.MustParsePrefix("10.1.2.3/32")})
	if !f(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("bad")
	}
	f = NewContainsIPFunc([]netaddr.IPPrefix{
		netip.MustParsePrefix("10.1.2.3/32"),
		netip.MustParsePrefix("::2/128"),
	})
	if !f(netip.MustParseAddr("::2")) {
		t.Fatal("bad")
	}
	f = NewContainsIPFunc([]netaddr.IPPrefix{
		netip.MustParsePrefix("10.1.2.3/32"),
		netip.MustParsePrefix("10.1.2.4/32"),
		netip.MustParsePrefix("::2/128"),
	})
	if !f(netip.MustParseAddr("10.1.2.4")) {
		t.Fatal("bad")
	}
}

var sinkIP netaddr.IP

func BenchmarkTailscaleServiceAddr(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sinkIP = TailscaleServiceIP()
	}
}

func TestUnmapVia(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"1.2.3.4", "1.2.3.4"}, // unchanged v4
		{"fd7a:115c:a1e0:b1a::bb:10.2.1.3", "10.2.1.3"},
		{"fd7a:115c:a1e0:b1b::bb:10.2.1.4", "fd7a:115c:a1e0:b1b:0:bb:a02:104"}, // "b1b",not "bia"
	}
	for _, tt := range tests {
		if got := UnmapVia(netip.MustParseAddr(tt.ip)).String(); got != tt.want {
			t.Errorf("for %q: got %q, want %q", tt.ip, got, tt.want)
		}
	}
}
