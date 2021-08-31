// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsaddr

import (
	"testing"

	"inet.af/netaddr"
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
	f := NewContainsIPFunc([]netaddr.IPPrefix{netaddr.MustParseIPPrefix("10.0.0.0/8")})
	if f(netaddr.MustParseIP("8.8.8.8")) {
		t.Fatal("bad")
	}
	if !f(netaddr.MustParseIP("10.1.2.3")) {
		t.Fatal("bad")
	}
	f = NewContainsIPFunc([]netaddr.IPPrefix{netaddr.MustParseIPPrefix("10.1.2.3/32")})
	if !f(netaddr.MustParseIP("10.1.2.3")) {
		t.Fatal("bad")
	}
	f = NewContainsIPFunc([]netaddr.IPPrefix{
		netaddr.MustParseIPPrefix("10.1.2.3/32"),
		netaddr.MustParseIPPrefix("::2/128"),
	})
	if !f(netaddr.MustParseIP("::2")) {
		t.Fatal("bad")
	}
	f = NewContainsIPFunc([]netaddr.IPPrefix{
		netaddr.MustParseIPPrefix("10.1.2.3/32"),
		netaddr.MustParseIPPrefix("10.1.2.4/32"),
		netaddr.MustParseIPPrefix("::2/128"),
	})
	if !f(netaddr.MustParseIP("10.1.2.4")) {
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
