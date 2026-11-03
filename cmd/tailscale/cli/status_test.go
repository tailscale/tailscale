// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/views"
)

func TestAdvertisedRoutes(t *testing.T) {
	prefixes := func(ss ...string) *views.Slice[netip.Prefix] {
		ps := make([]netip.Prefix, 0, len(ss))
		for _, s := range ss {
			ps = append(ps, netip.MustParsePrefix(s))
		}
		v := views.SliceOf(ps)
		return &v
	}
	addrs := func(ss ...string) []netip.Addr {
		as := make([]netip.Addr, 0, len(ss))
		for _, s := range ss {
			as = append(as, netip.MustParseAddr(s))
		}
		return as
	}

	tests := []struct {
		name string
		ps   *ipnstate.PeerStatus
		want []string
	}{
		{
			name: "no AllowedIPs",
			ps:   &ipnstate.PeerStatus{TailscaleIPs: addrs("100.64.0.1")},
			want: nil,
		},
		{
			name: "only self IPs",
			ps: &ipnstate.PeerStatus{
				TailscaleIPs: addrs("100.64.0.1", "fd7a:115c:a1e0::1"),
				AllowedIPs:   prefixes("100.64.0.1/32", "fd7a:115c:a1e0::1/128"),
			},
			want: nil,
		},
		{
			name: "subnet router",
			ps: &ipnstate.PeerStatus{
				TailscaleIPs: addrs("100.64.0.1", "fd7a:115c:a1e0::1"),
				AllowedIPs:   prefixes("100.64.0.1/32", "fd7a:115c:a1e0::1/128", "192.0.2.0/24"),
			},
			want: []string{"192.0.2.0/24"},
		},
		{
			name: "exit node",
			ps: &ipnstate.PeerStatus{
				TailscaleIPs: addrs("100.64.0.1"),
				AllowedIPs:   prefixes("100.64.0.1/32", "0.0.0.0/0", "::/0"),
			},
			want: []string{"0.0.0.0/0", "::/0"},
		},
		{
			name: "other node's single IP is a route, not self",
			ps: &ipnstate.PeerStatus{
				TailscaleIPs: addrs("100.64.0.1"),
				AllowedIPs:   prefixes("100.64.0.1/32", "100.64.0.2/32"),
			},
			want: []string{"100.64.0.2/32"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := advertisedRoutes(tt.ps); !slices.Equal(got, tt.want) {
				t.Errorf("advertisedRoutes() = %v, want %v", got, tt.want)
			}
		})
	}
}
