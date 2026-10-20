// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routemanager

import (
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

func prefixView(ss ...string) views.Slice[netip.Prefix] {
	pfxs := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		pfxs[i] = pfx(s)
	}
	return views.SliceOf(pfxs)
}

func TestSubnetRouteFilters(t *testing.T) {
	routes := []string{
		"10.0.0.0/8", "10.2.0.0/24", "10.30.0.0/24", "192.0.2.1/32",
		"2001:db8::/32", "2001:db8:1::/48", "2001:db8:2::/48",
	}
	tests := []struct {
		name  string
		prefs Prefs
		want  []string
	}{
		{
			name:  "unrestricted",
			prefs: Prefs{RouteAll: true},
			want:  routes,
		},
		{
			name:  "disabled_with_allow",
			prefs: Prefs{AcceptRoutesAllow: prefixView("0.0.0.0/0", "::/0")},
		},
		{
			name:  "allow_exact_and_contained",
			prefs: Prefs{RouteAll: true, AcceptRoutesAllow: prefixView("10.2.0.0/24", "2001:db8::/32")},
			want:  []string{"10.2.0.0/24", "2001:db8::/32", "2001:db8:1::/48", "2001:db8:2::/48"},
		},
		{
			name:  "allow_does_not_split_supernet",
			prefs: Prefs{RouteAll: true, AcceptRoutesAllow: prefixView("10.2.0.0/25", "2001:db8:1::/64")},
		},
		{
			name:  "allow_does_not_combine_prefixes",
			prefs: Prefs{RouteAll: true, AcceptRoutesAllow: prefixView("10.2.0.0/25", "10.2.0.128/25")},
		},
		{
			name:  "deny_local_and_covering_routes",
			prefs: Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("10.2.0.0/24", "2001:db8:1::/48")},
			want:  []string{"10.30.0.0/24", "192.0.2.1/32", "2001:db8:2::/48"},
		},
		{
			name:  "deny_subprefix",
			prefs: Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("10.2.0.128/25", "2001:db8:1::1/128")},
			want:  []string{"10.30.0.0/24", "192.0.2.1/32", "2001:db8:2::/48"},
		},
		{
			name:  "deny_supernet",
			prefs: Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("10.0.0.0/8", "2001:db8::/32")},
			want:  []string{"192.0.2.1/32"},
		},
		{
			name: "deny_overrides_allow",
			prefs: Prefs{
				RouteAll:          true,
				AcceptRoutesAllow: prefixView("10.0.0.0/8", "2001:db8::/32"),
				AcceptRoutesDeny:  prefixView("10.2.0.0/24", "2001:db8:1::/48"),
			},
			want: []string{"10.30.0.0/24", "2001:db8:2::/48"},
		},
		{
			name:  "allow_ipv4_only",
			prefs: Prefs{RouteAll: true, AcceptRoutesAllow: prefixView("0.0.0.0/0")},
			want:  routes[:4],
		},
		{
			name:  "deny_ipv4_only",
			prefs: Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("0.0.0.0/0")},
			want:  routes[4:],
		},
		{
			name:  "deny_ipv6_only",
			prefs: Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("::/0")},
			want:  routes[:4],
		},
		{
			name:  "allow_single_address",
			prefs: Prefs{RouteAll: true, AcceptRoutesAllow: prefixView("192.0.2.1/32")},
			want:  []string{"192.0.2.1/32"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := New(t.Logf)
			p := peer1()
			p.Routes = prefixView(routes...).AsSlice()
			res := commit(rm, func(m *Mutation) {
				m.SetPrefs(tt.prefs)
				m.upsertPeer(p)
			})
			wantOSRoutes(t, rm, append([]string{"100.64.0.1/32", "fd7a:115c:a1e0::/48"}, tt.want...)...)
			wantAllowed := append([]string{"100.64.0.1/32", "fd7a:115c:a1e0::1/128"}, tt.want...)
			wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{k1: wantAllowed})
			gotAllowed, ok := rm.PeerAllowedIPs(p.ID)
			wantPfxs := prefixView(wantAllowed...).AsSlice()
			tsaddr.SortPrefixes(wantPfxs)
			if !ok || !slices.Equal(gotAllowed, wantPfxs) {
				t.Errorf("PeerAllowedIPs = %v, %v; want %v, true", gotAllowed, ok, wantPfxs)
			}
			for _, route := range routes {
				got, ok := rm.Outbound().Get(pfx(route))
				if want := slices.Contains(tt.want, route); ok != want || (ok && got.Key != k1) {
					t.Errorf("Outbound.Get(%s) = %v, %v; want peer 1 present=%v", route, got, ok, want)
				}
			}
			wantOutbound(t, rm, "100.64.0.1", k1, true)
			wantOutbound(t, rm, "fd7a:115c:a1e0::1", k1, true)
		})
	}
}

func TestSubnetRouteFilterUpdates(t *testing.T) {
	rm := New(t.Logf)
	p := peer1()
	p.Routes = prefixView("10.2.0.0/24", "10.30.0.0/24").AsSlice()
	commit(rm, func(m *Mutation) {
		m.upsertPeer(p)
		m.SetPrefs(Prefs{RouteAll: true})
	})
	oldOut, oldOS := rm.Outbound(), rm.OSRoutes()
	denyHome := Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("10.2.0.0/24")}
	res := commit(rm, func(m *Mutation) { m.SetPrefs(denyHome) })
	if !res.PrefsChanged || !res.OutboundChanged || !res.OSRoutesChanged {
		t.Errorf("excluding existing route: %+v", res)
	}
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "10.30.0.0/24"},
	})
	wantOutbound(t, rm, "10.2.0.1", key.NodePublic{}, false)
	wantOutbound(t, rm, "10.30.0.1", k1, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "10.30.0.0/24")
	if _, ok := oldOut.Get(pfx("10.2.0.0/24")); !ok || !oldOS.Get(pfx("10.2.0.0/24")) {
		t.Error("prefs update changed an old snapshot")
	}

	// Independently allocated views with equal contents are a no-op.
	oldOut, oldOS = rm.Outbound(), rm.OSRoutes()
	res = commit(rm, func(m *Mutation) {
		m.SetPrefs(Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("10.2.0.0/24")})
	})
	if res.PrefsChanged || res.OutboundChanged || res.OSRoutesChanged || res.AllowedIPs != nil || rm.Outbound() != oldOut || rm.OSRoutes() != oldOS {
		t.Errorf("equal filter contents changed routing: %+v", res)
	}

	// A later netmap update must not restore the denied subnet by
	// advertising a covering route. An unrelated new route is accepted.
	p.Routes = prefixView("10.0.0.0/8", "10.30.0.0/24", "192.0.2.0/24").AsSlice()
	res = commit(rm, func(m *Mutation) { m.upsertPeer(p) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "10.30.0.0/24", "192.0.2.0/24"},
	})
	wantOutbound(t, rm, "10.2.0.1", key.NodePublic{}, false)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "10.30.0.0/24", "192.0.2.0/24")

	// Changing only the allow list removes the unrelated route.
	denyHome.AcceptRoutesAllow = prefixView("10.30.0.0/24")
	res = commit(rm, func(m *Mutation) { m.SetPrefs(denyHome) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "10.30.0.0/24"},
	})
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "10.30.0.0/24")
	res = commit(rm, func(m *Mutation) {
		m.SetPrefs(Prefs{
			RouteAll:          true,
			AcceptRoutesAllow: prefixView("10.30.0.0/24"),
			AcceptRoutesDeny:  prefixView("10.2.0.0/24"),
		})
	})
	if res.PrefsChanged || res.OutboundChanged || res.OSRoutesChanged || res.AllowedIPs != nil {
		t.Errorf("equal allow and deny lists changed routing: %+v", res)
	}

	// Clearing the filters restores all advertised routes without
	// requiring another netmap update.
	res = commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "10.0.0.0/8", "10.30.0.0/24", "192.0.2.0/24"},
	})
	wantOutbound(t, rm, "10.2.0.1", k1, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "10.0.0.0/8", "10.30.0.0/24", "192.0.2.0/24")

	// Nil and empty filters are equivalent.
	res = commit(rm, func(m *Mutation) {
		m.SetPrefs(Prefs{RouteAll: true, AcceptRoutesAllow: prefixView(), AcceptRoutesDeny: prefixView()})
	})
	if res.PrefsChanged || res.OutboundChanged || res.OSRoutesChanged || res.AllowedIPs != nil {
		t.Errorf("empty filter changed routing: %+v", res)
	}
}

func TestSubnetRouteFiltersNonSubnetRoutes(t *testing.T) {
	rm := New(t.Logf)
	p := peer1()
	p.Routes = prefixView("0.0.0.0/0", "::/0", "10.2.0.0/24", "fe80::1234/128", "100.64.0.1/32").AsSlice()
	prefs := Prefs{
		RouteAll:          true,
		AcceptRoutesAllow: prefixView("192.0.2.0/24"),
		AcceptRoutesDeny:  prefixView("0.0.0.0/0", "::/0"),
	}
	res := commit(rm, func(m *Mutation) {
		m.upsertPeer(p)
		m.SetPrefs(prefs)
		m.SetExtraAllowedIPs(map[tailcfg.NodeID][]netip.Prefix{
			1: prefixView("fe80::1234/128", "10.2.0.0/24").AsSlice(),
		})
	})
	// Self addresses and extra allowed IPs survive the filters, even
	// when also present among the peer's advertised routes. Extras do
	// not cause the denied advertised route to be installed in the OS.
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "fe80::1234/128", "10.2.0.0/24"},
	})
	wantOutbound(t, rm, "100.64.0.1", k1, true)
	wantOutbound(t, rm, "fd7a:115c:a1e0::1", k1, true)
	wantOutbound(t, rm, "fe80::1234", k1, true)
	wantOutbound(t, rm, "10.2.0.1", k1, true)
	wantOutbound(t, rm, "8.8.8.8", key.NodePublic{}, false)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48")

	// A selected exit node still carries its /0 routes. Rejecting a
	// subnet route is not a packet ACL or an exit-node LAN bypass.
	prefs.ExitNodeID, prefs.ExitNodeSelected = 1, true
	res = commit(rm, func(m *Mutation) { m.SetPrefs(prefs) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "fe80::1234/128", "10.2.0.0/24", "0.0.0.0/0", "::/0"},
	})
	wantOutbound(t, rm, "8.8.8.8", k1, true)
	wantOutbound(t, rm, "2001:db8::1", k1, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "0.0.0.0/0", "::/0")

	// An unresolved exit node retains its blackhole routes.
	prefs.ExitNodeID = 0
	commit(rm, func(m *Mutation) { m.SetPrefs(prefs) })
	wantOutbound(t, rm, "8.8.8.8", key.NodePublic{}, false)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "0.0.0.0/0", "::/0")
}

func TestSubnetRouteFiltersRouteOnlyPeer(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) {
		m.upsertPeer(peerView{ID: 1, Key: k1, Routes: prefixView("10.2.0.0/24").AsSlice()})
		m.SetPrefs(Prefs{RouteAll: true})
	})
	res := commit(rm, func(m *Mutation) {
		m.SetPrefs(Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("10.2.0.0/24")})
	})
	// A peer with no accepted prefixes must be removed from WireGuard.
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{k1: nil})
	if got, ok := rm.PeerAllowedIPs(1); ok {
		t.Errorf("PeerAllowedIPs = %v, true; want no allowed prefixes", got)
	}
	wantOutbound(t, rm, "10.2.0.1", key.NodePublic{}, false)
	wantOSRoutes(t, rm)

	res = commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{k1: {"10.2.0.0/24"}})
	wantOutbound(t, rm, "10.2.0.1", k1, true)
	wantOSRoutes(t, rm, "10.2.0.0/24")
}

func TestSubnetRouteFiltersExtraRouteGating(t *testing.T) {
	tests := []struct {
		name       string
		prefs      Prefs
		wantSubnet bool
		wantExit   bool
	}{
		{name: "disabled"},
		{name: "enabled", prefs: Prefs{RouteAll: true}, wantSubnet: true},
		{
			name:       "filtered",
			prefs:      Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("0.0.0.0/0", "::/0")},
			wantSubnet: true,
		},
		{name: "exit_selected", prefs: Prefs{ExitNodeID: 1}, wantExit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := New(t.Logf)
			p := peer1()
			p.Routes = prefixView("10.2.0.0/24", "0.0.0.0/0", "::/0").AsSlice()
			res := commit(rm, func(m *Mutation) {
				m.upsertPeer(p)
				m.SetPrefs(tt.prefs)
				m.SetExtraAllowedIPs(map[tailcfg.NodeID][]netip.Prefix{
					1: prefixView("10.2.0.0/24", "0.0.0.0/0", "::/0", "192.0.2.1/32").AsSlice(),
				})
			})
			// An extra that is also advertised retains the pre-filter
			// RouteAll and exit-node gating. An extra-only prefix needs
			// neither and is always eligible outside the OS route set.
			wantAllowed := []string{"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "192.0.2.1/32"}
			wantOS := []string{"100.64.0.1/32", "fd7a:115c:a1e0::/48"}
			if tt.wantSubnet {
				wantAllowed = append(wantAllowed, "10.2.0.0/24")
				if tt.prefs.AcceptRoutesDeny.Len() == 0 {
					wantOS = append(wantOS, "10.2.0.0/24")
				}
			}
			if tt.wantExit {
				wantAllowed = append(wantAllowed, "0.0.0.0/0", "::/0")
				wantOS = append(wantOS, "0.0.0.0/0", "::/0")
			}
			wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{k1: wantAllowed})
			wantOSRoutes(t, rm, wantOS...)
			for route, want := range map[string]bool{
				"10.2.0.0/24": tt.wantSubnet,
				"0.0.0.0/0":   tt.wantExit,
				"::/0":        tt.wantExit,
			} {
				if _, got := rm.Outbound().Get(pfx(route)); got != want {
					t.Errorf("Outbound.Get(%s) present=%v, want %v", route, got, want)
				}
			}
			wantOutbound(t, rm, "192.0.2.1", k1, true)
		})
	}
}

func TestSubnetRouteFiltersSharedRoutes(t *testing.T) {
	rm := New(t.Logf)
	a, b := peer1(), peer2()
	a.Routes = prefixView("10.2.0.0/24", "10.30.0.0/24").AsSlice()
	b.Routes = slices.Clone(a.Routes)
	commit(rm, func(m *Mutation) {
		m.upsertPeer(a)
		m.upsertPeer(b)
		m.SetPrefs(Prefs{RouteAll: true, AcceptRoutesDeny: prefixView("10.2.0.0/24")})
	})
	wantOutbound(t, rm, "10.2.0.1", key.NodePublic{}, false)
	wantOutbound(t, rm, "10.30.0.1", k1, true)

	res := commit(rm, func(m *Mutation) {
		m.SetScore(2, pfx("10.2.0.0/24"), 100)
		m.SetScore(2, pfx("10.30.0.0/24"), 100)
	})
	wantChangedAllowedIPs(t, res, nil)
	wantOutbound(t, rm, "10.2.0.1", key.NodePublic{}, false)
	wantOutbound(t, rm, "10.30.0.1", k2, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "100.64.0.2/32", "fd7a:115c:a1e0::/48", "10.30.0.0/24")

	// Removing the preferred router fails over only the accepted route.
	commit(rm, func(m *Mutation) { m.RemovePeer(2) })
	wantOutbound(t, rm, "10.2.0.1", key.NodePublic{}, false)
	wantOutbound(t, rm, "10.30.0.1", k1, true)

	// A later advertisement by another router cannot restore a
	// rejected route, regardless of its score.
	res = commit(rm, func(m *Mutation) {
		m.upsertPeer(b)
		m.SetScore(2, pfx("10.2.0.0/24"), 100)
	})
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k2: {"100.64.0.2/32", "fd7a:115c:a1e0::2/128", "10.30.0.0/24"},
	})
	wantOutbound(t, rm, "10.2.0.1", key.NodePublic{}, false)
}
