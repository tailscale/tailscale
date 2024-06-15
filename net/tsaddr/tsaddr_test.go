// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsaddr

import (
	"net/netip"
	"testing"

	"tailscale.com/net/netaddr"
	"tailscale.com/tstest"
	"tailscale.com/types/views"
)

func TestInCrostiniRange(t *testing.T) {
	tests := []struct {
		ip   netip.Addr
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

func TestTailscaleServiceIP(t *testing.T) {
	got := TailscaleServiceIP().String()
	want := "100.100.100.100"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	if TailscaleServiceIPString != want {
		t.Error("TailscaleServiceIPString is not consistent")
	}
}

func TestTailscaleServiceIPv6(t *testing.T) {
	got := TailscaleServiceIPv6().String()
	want := "fd7a:115c:a1e0::53"
	if got != want {
		t.Errorf("got %q; want %q", got, want)
	}
	if TailscaleServiceIPv6String != want {
		t.Error("TailscaleServiceIPv6String is not consistent")
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

func pp(ss ...string) (ret []netip.Prefix) {
	for _, s := range ss {
		ret = append(ret, netip.MustParsePrefix(s))
	}
	return
}

func aa(ss ...string) (ret []netip.Addr) {
	for _, s := range ss {
		ret = append(ret, netip.MustParseAddr(s))
	}
	return
}

var newContainsIPFuncTests = []struct {
	name    string
	pfx     []netip.Prefix
	want    string
	wantIn  []netip.Addr
	wantOut []netip.Addr
}{
	{
		name:    "empty",
		pfx:     pp(),
		want:    "empty",
		wantOut: aa("8.8.8.8"),
	},
	{
		name:    "cidr-list-1",
		pfx:     pp("10.0.0.0/8"),
		want:    "linear-contains",
		wantIn:  aa("10.0.0.1", "10.2.3.4"),
		wantOut: aa("8.8.8.8"),
	},
	{
		name:    "cidr-list-2",
		pfx:     pp("1.0.0.0/8", "3.0.0.0/8"),
		want:    "linear-contains",
		wantIn:  aa("1.0.0.1", "3.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name:    "cidr-list-3",
		pfx:     pp("1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8"),
		want:    "linear-contains",
		wantIn:  aa("1.0.0.1", "5.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name:    "cidr-list-4",
		pfx:     pp("1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8", "7.0.0.0/8"),
		want:    "linear-contains",
		wantIn:  aa("1.0.0.1", "7.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name:    "cidr-list-5",
		pfx:     pp("1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8", "7.0.0.0/8", "9.0.0.0/8"),
		want:    "linear-contains",
		wantIn:  aa("1.0.0.1", "9.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name: "cidr-list-10",
		pfx: pp("1.0.0.0/8", "3.0.0.0/8", "5.0.0.0/8", "7.0.0.0/8", "9.0.0.0/8",
			"11.0.0.0/8", "13.0.0.0/8", "15.0.0.0/8", "17.0.0.0/8", "19.0.0.0/8"),
		want:    "bart", // big enough that bart is faster than linear-contains
		wantIn:  aa("1.0.0.1", "19.0.0.1"),
		wantOut: aa("2.0.0.1"),
	},
	{
		name:    "one-ip",
		pfx:     pp("10.1.0.0/32"),
		want:    "one-ip",
		wantIn:  aa("10.1.0.0"),
		wantOut: aa("10.0.0.9"),
	},
	{
		name:    "two-ip",
		pfx:     pp("10.1.0.0/32", "10.2.0.0/32"),
		want:    "two-ip",
		wantIn:  aa("10.1.0.0", "10.2.0.0"),
		wantOut: aa("8.8.8.8"),
	},
	{
		name:    "three-ip",
		pfx:     pp("10.1.0.0/32", "10.2.0.0/32", "10.3.0.0/32"),
		want:    "ip-map",
		wantIn:  aa("10.1.0.0", "10.2.0.0"),
		wantOut: aa("8.8.8.8"),
	},
}

func BenchmarkNewContainsIPFunc(b *testing.B) {
	for _, tt := range newContainsIPFuncTests {
		b.Run(tt.name, func(b *testing.B) {
			f := NewContainsIPFunc(views.SliceOf(tt.pfx))
			for i := 0; i < b.N; i++ {
				for _, ip := range tt.wantIn {
					if !f(ip) {
						b.Fatal("unexpected false")
					}
				}
				for _, ip := range tt.wantOut {
					if f(ip) {
						b.Fatal("unexpected true")
					}
				}
			}
		})
	}
}

func TestNewContainsIPFunc(t *testing.T) {
	for _, tt := range newContainsIPFuncTests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			tstest.Replace(t, &pathForTest, func(path string) { got = path })

			f := NewContainsIPFunc(views.SliceOf(tt.pfx))
			if got != tt.want {
				t.Errorf("func type = %q; want %q", got, tt.want)
			}
			for _, ip := range tt.wantIn {
				if !f(ip) {
					t.Errorf("match(%v) = false; want true", ip)
				}
			}
			for _, ip := range tt.wantOut {
				if f(ip) {
					t.Errorf("match(%v) = true; want false", ip)
				}
			}
		})
	}
}

var sinkIP netip.Addr

func BenchmarkTailscaleServiceAddr(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
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
