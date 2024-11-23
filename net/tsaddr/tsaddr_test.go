// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsaddr

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/net/netaddr"
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

func TestIsExitNodeRoute(t *testing.T) {
	tests := []struct {
		pref netip.Prefix
		want bool
	}{
		{
			pref: AllIPv4(),
			want: true,
		},
		{
			pref: AllIPv6(),
			want: true,
		},
		{
			pref: netip.MustParsePrefix("1.1.1.1/0"),
			want: false,
		},
		{
			pref: netip.MustParsePrefix("1.1.1.1/1"),
			want: false,
		},
		{
			pref: netip.MustParsePrefix("192.168.0.0/24"),
			want: false,
		},
	}

	for _, tt := range tests {
		if got := IsExitRoute(tt.pref); got != tt.want {
			t.Errorf("for %q: got %v, want %v", tt.pref, got, tt.want)
		}
	}
}

func TestWithoutExitRoutes(t *testing.T) {
	tests := []struct {
		prefs []netip.Prefix
		want  []netip.Prefix
	}{
		{
			prefs: []netip.Prefix{AllIPv4(), AllIPv6()},
			want:  []netip.Prefix{},
		},
		{
			prefs: []netip.Prefix{AllIPv4()},
			want:  []netip.Prefix{AllIPv4()},
		},
		{
			prefs: []netip.Prefix{AllIPv4(), AllIPv6(), netip.MustParsePrefix("10.0.0.0/10")},
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/10")},
		},
		{
			prefs: []netip.Prefix{AllIPv6(), netip.MustParsePrefix("10.0.0.0/10")},
			want:  []netip.Prefix{AllIPv6(), netip.MustParsePrefix("10.0.0.0/10")},
		},
	}

	for _, tt := range tests {
		got := WithoutExitRoutes(views.SliceOf(tt.prefs))
		if diff := cmp.Diff(tt.want, got.AsSlice(), cmpopts.EquateEmpty(), cmp.Comparer(func(a, b netip.Prefix) bool { return a == b })); diff != "" {
			t.Errorf("unexpected route difference (-want +got):\n%s", diff)
		}
	}
}

func TestWithoutExitRoute(t *testing.T) {
	tests := []struct {
		prefs []netip.Prefix
		want  []netip.Prefix
	}{
		{
			prefs: []netip.Prefix{AllIPv4(), AllIPv6()},
			want:  []netip.Prefix{},
		},
		{
			prefs: []netip.Prefix{AllIPv4()},
			want:  []netip.Prefix{},
		},
		{
			prefs: []netip.Prefix{AllIPv4(), AllIPv6(), netip.MustParsePrefix("10.0.0.0/10")},
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/10")},
		},
		{
			prefs: []netip.Prefix{AllIPv6(), netip.MustParsePrefix("10.0.0.0/10")},
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/10")},
		},
	}

	for _, tt := range tests {
		got := WithoutExitRoute(views.SliceOf(tt.prefs))
		if diff := cmp.Diff(tt.want, got.AsSlice(), cmpopts.EquateEmpty(), cmp.Comparer(func(a, b netip.Prefix) bool { return a == b })); diff != "" {
			t.Errorf("unexpected route difference (-want +got):\n%s", diff)
		}
	}
}

func TestContainsExitRoute(t *testing.T) {
	tests := []struct {
		prefs []netip.Prefix
		want  bool
	}{
		{
			prefs: []netip.Prefix{AllIPv4(), AllIPv6()},
			want:  true,
		},
		{
			prefs: []netip.Prefix{AllIPv4()},
			want:  true,
		},
		{
			prefs: []netip.Prefix{AllIPv4(), AllIPv6(), netip.MustParsePrefix("10.0.0.0/10")},
			want:  true,
		},
		{
			prefs: []netip.Prefix{AllIPv6(), netip.MustParsePrefix("10.0.0.0/10")},
			want:  true,
		},
		{
			prefs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/10")},
			want:  false,
		},
	}

	for _, tt := range tests {
		if got := ContainsExitRoute(views.SliceOf(tt.prefs)); got != tt.want {
			t.Errorf("for %q: got %v, want %v", tt.prefs, got, tt.want)
		}
	}
}

func TestIsTailscaleIPv4(t *testing.T) {
	tests := []struct {
		in   netip.Addr
		want bool
	}{
		{
			in:   netip.MustParseAddr("100.67.19.57"),
			want: true,
		},
		{
			in:   netip.MustParseAddr("10.10.10.10"),
			want: false,
		},
		{

			in:   netip.MustParseAddr("fd7a:115c:a1e0:3f2b:7a1d:4e88:9c2b:7f01"),
			want: false,
		},
		{
			in:   netip.MustParseAddr("bc9d:0aa0:1f0a:69ab:eb5c:28e0:5456:a518"),
			want: false,
		},
		{
			in:   netip.MustParseAddr("100.115.92.157"),
			want: false,
		},
	}
	for _, tt := range tests {
		if got := IsTailscaleIPv4(tt.in); got != tt.want {
			t.Errorf("IsTailscaleIPv4(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestIsTailscaleIP(t *testing.T) {
	tests := []struct {
		in   netip.Addr
		want bool
	}{
		{
			in:   netip.MustParseAddr("100.67.19.57"),
			want: true,
		},
		{
			in:   netip.MustParseAddr("10.10.10.10"),
			want: false,
		},
		{

			in:   netip.MustParseAddr("fd7a:115c:a1e0:3f2b:7a1d:4e88:9c2b:7f01"),
			want: true,
		},
		{
			in:   netip.MustParseAddr("bc9d:0aa0:1f0a:69ab:eb5c:28e0:5456:a518"),
			want: false,
		},
		{
			in:   netip.MustParseAddr("100.115.92.157"),
			want: false,
		},
	}
	for _, tt := range tests {
		if got := IsTailscaleIP(tt.in); got != tt.want {
			t.Errorf("IsTailscaleIP(%v) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
