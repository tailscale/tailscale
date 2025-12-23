// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || freebsd

package osrouter

import (
	"net/netip"
	"runtime"
	"testing"

	"tailscale.com/net/tsaddr"
)

func TestSplitDefaultRoutes(t *testing.T) {
	// This test validates the splitDefaultRoutes function which converts
	// /0 routes into split /1 routes on macOS.
	tests := []struct {
		name   string
		input  []netip.Prefix
		want   []netip.Prefix // expected on macOS
		wantNonMac []netip.Prefix // expected on non-macOS (same as input)
	}{
		{
			name:   "empty",
			input:  nil,
			want:   nil,
			wantNonMac: nil,
		},
		{
			name:  "single regular route",
			input: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			wantNonMac: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		},
		{
			name:  "ipv4 default route only",
			input: []netip.Prefix{tsaddr.AllIPv4()},
			want: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/1"),
				netip.MustParsePrefix("128.0.0.0/1"),
			},
			wantNonMac: []netip.Prefix{tsaddr.AllIPv4()},
		},
		{
			name:  "ipv6 default route only",
			input: []netip.Prefix{tsaddr.AllIPv6()},
			want: []netip.Prefix{
				netip.MustParsePrefix("::/1"),
				netip.MustParsePrefix("8000::/1"),
			},
			wantNonMac: []netip.Prefix{tsaddr.AllIPv6()},
		},
		{
			name: "both default routes",
			input: []netip.Prefix{
				tsaddr.AllIPv4(),
				tsaddr.AllIPv6(),
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/1"),
				netip.MustParsePrefix("128.0.0.0/1"),
				netip.MustParsePrefix("::/1"),
				netip.MustParsePrefix("8000::/1"),
			},
			wantNonMac: []netip.Prefix{
				tsaddr.AllIPv4(),
				tsaddr.AllIPv6(),
			},
		},
		{
			name: "mixed routes with defaults",
			input: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.0/10"),
				tsaddr.AllIPv4(),
				netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
			},
			want: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.0/10"),
				netip.MustParsePrefix("0.0.0.0/1"),
				netip.MustParsePrefix("128.0.0.0/1"),
				netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
			},
			wantNonMac: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.0/10"),
				tsaddr.AllIPv4(),
				netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitDefaultRoutes(tt.input)

			var want []netip.Prefix
			if runtime.GOOS == "darwin" {
				want = tt.want
			} else {
				want = tt.wantNonMac
			}

			if len(got) != len(want) {
				t.Errorf("splitDefaultRoutes() returned %d routes, want %d\ngot:  %v\nwant: %v",
					len(got), len(want), got, want)
				return
			}

			for i := range got {
				if got[i] != want[i] {
					t.Errorf("splitDefaultRoutes()[%d] = %v, want %v", i, got[i], want[i])
				}
			}
		})
	}
}

func TestSplitRouteCoverage(t *testing.T) {
	// Verify that the two /1 routes together cover all of IPv4 space
	// This is important for the exit node functionality
	if runtime.GOOS != "darwin" {
		t.Skip("split routes only apply to darwin")
	}

	routes := splitDefaultRoutes([]netip.Prefix{tsaddr.AllIPv4()})
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}

	route1 := routes[0] // 0.0.0.0/1
	route2 := routes[1] // 128.0.0.0/1

	// Test that various IPs are covered by exactly one route
	testIPs := []struct {
		ip      string
		inFirst bool // should be in first /1 route (0.0.0.0/1)
	}{
		{"0.0.0.0", true},
		{"1.1.1.1", true},
		{"8.8.8.8", true},
		{"100.64.0.1", true},
		{"127.255.255.255", true},
		{"128.0.0.0", false},
		{"192.168.1.1", false},
		{"224.0.0.1", false},
		{"255.255.255.255", false},
	}

	for _, tt := range testIPs {
		ip := netip.MustParseAddr(tt.ip)
		in1 := route1.Contains(ip)
		in2 := route2.Contains(ip)

		if tt.inFirst {
			if !in1 || in2 {
				t.Errorf("IP %s should be in first route only, got in1=%v in2=%v", tt.ip, in1, in2)
			}
		} else {
			if in1 || !in2 {
				t.Errorf("IP %s should be in second route only, got in1=%v in2=%v", tt.ip, in1, in2)
			}
		}
	}
}

func TestIPv6SplitRouteCoverage(t *testing.T) {
	// Verify that the two /1 routes together cover all of IPv6 space
	if runtime.GOOS != "darwin" {
		t.Skip("split routes only apply to darwin")
	}

	routes := splitDefaultRoutes([]netip.Prefix{tsaddr.AllIPv6()})
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}

	route1 := routes[0] // ::/1
	route2 := routes[1] // 8000::/1

	// Test that various IPs are covered by exactly one route
	testIPs := []struct {
		ip      string
		inFirst bool // should be in first /1 route (::/1)
	}{
		{"::", true},
		{"::1", true},
		{"2001:4860:4860::8888", true}, // Google DNS
		{"fd7a:115c:a1e0::1", false},   // Tailscale ULA (starts with 0xf, so in 8000::/1)
		{"7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"8000::", false},
		{"8000::1", false},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
	}

	for _, tt := range testIPs {
		ip := netip.MustParseAddr(tt.ip)
		in1 := route1.Contains(ip)
		in2 := route2.Contains(ip)

		if tt.inFirst {
			if !in1 || in2 {
				t.Errorf("IP %s should be in first route only, got in1=%v in2=%v", tt.ip, in1, in2)
			}
		} else {
			if in1 || !in2 {
				t.Errorf("IP %s should be in second route only, got in1=%v in2=%v", tt.ip, in1, in2)
			}
		}
	}
}
