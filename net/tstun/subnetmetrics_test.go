// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tstun

import (
	"net/netip"
	"testing"

	"tailscale.com/util/usermetric"
)

// routeCountsFor returns the four counter values for the given route, or
// zeroes if the route is not being counted.
func routeCountsFor(t *testing.T, sc *subnetCounters, route string) (txBytes, rxBytes, txPackets, rxPackets int64) {
	t.Helper()
	pfx := netip.MustParsePrefix(route)
	rc := sc.forRoute(pfx)
	if rc == nil {
		return 0, 0, 0, 0
	}
	return rc.txBytes.Value(), rc.rxBytes.Value(), rc.txPackets.Value(), rc.rxPackets.Value()
}

func TestSubnetCountersAttribution(t *testing.T) {
	tests := []struct {
		name string
		// routes advertised by this node.
		routes []string
		// remote is the non-Tailscale endpoint of the packet.
		remote string
		// wantRoute is the route the traffic should be attributed to,
		// or "" if the packet should not be counted at all.
		wantRoute string
	}{
		{
			name:      "within advertised prefix",
			routes:    []string{"10.1.0.0/16"},
			remote:    "10.1.2.3",
			wantRoute: "10.1.0.0/16",
		},
		{
			name:      "outside all prefixes is not counted",
			routes:    []string{"10.1.0.0/16"},
			remote:    "192.0.2.5",
			wantRoute: "",
		},
		{
			name:      "longest prefix wins",
			routes:    []string{"10.0.0.0/8", "10.1.0.0/16"},
			remote:    "10.1.2.3",
			wantRoute: "10.1.0.0/16",
		},
		{
			name:      "less specific route still matches outside the specific one",
			routes:    []string{"10.0.0.0/8", "10.1.0.0/16"},
			remote:    "10.9.9.9",
			wantRoute: "10.0.0.0/8",
		},
		{
			name:      "IPv4 exit route is excluded",
			routes:    []string{"0.0.0.0/0"},
			remote:    "192.0.2.5",
			wantRoute: "",
		},
		{
			name:      "IPv6 exit route is excluded",
			routes:    []string{"::/0"},
			remote:    "2001:db8::1",
			wantRoute: "",
		},
		{
			name:      "IPv6 subnet route",
			routes:    []string{"2001:db8::/32"},
			remote:    "2001:db8::1",
			wantRoute: "2001:db8::/32",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := newSubnetCounters(new(usermetric.Registry))
			sc.setRoutes(mustPrefixes(t, tt.routes))

			remote := netip.MustParseAddr(tt.remote)
			got := sc.forAddr(remote)

			if tt.wantRoute == "" {
				if got != nil {
					t.Fatalf("forAddr(%v) = counters for a route; want no match", remote)
				}
				return
			}
			if got == nil {
				t.Fatalf("forAddr(%v) = no match; want counters for %v", remote, tt.wantRoute)
			}
			want := sc.forRoute(netip.MustParsePrefix(tt.wantRoute))
			if want == nil {
				t.Fatalf("route %v has no counters registered", tt.wantRoute)
			}
			if got != want {
				t.Errorf("forAddr(%v) attributed to the wrong route; want %v", remote, tt.wantRoute)
			}
		})
	}
}

func mustPrefixes(t *testing.T, ss []string) []netip.Prefix {
	t.Helper()
	ps := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}
