// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routemanager

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

var (
	k1 = key.NewNode().Public()
	k2 = key.NewNode().Public()
	k3 = key.NewNode().Public()
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

// peer1 is a basic peer with self addresses only.
func peer1() peerView {
	return peerView{
		ID:  1,
		Key: k1,
		SelfAddrs: []netip.Prefix{
			pfx("100.64.0.1/32"),
			pfx("fd7a:115c:a1e0::1/128"),
		},
	}
}

func peer2() peerView {
	return peerView{
		ID:  2,
		Key: k2,
		SelfAddrs: []netip.Prefix{
			pfx("100.64.0.2/32"),
			pfx("fd7a:115c:a1e0::2/128"),
		},
	}
}

// commit applies fn within a single mutation and returns the Result.
func commit(rm *RouteManager, fn func(*Mutation)) Result {
	m := rm.Begin()
	fn(m)
	return m.Commit()
}

func wantOutbound(t *testing.T, rm *RouteManager, ip string, want key.NodePublic, wantOK bool) {
	t.Helper()
	got, ok := rm.Outbound().Lookup(addr(ip))
	if ok != wantOK || (ok && got.Key != want) {
		var gotKey key.NodePublic
		if got != nil {
			gotKey = got.Key
		}
		t.Errorf("Outbound lookup %s = %v, %v; want %v, %v", ip, gotKey.ShortString(), ok, want.ShortString(), wantOK)
	}
}

func wantOSRoutes(t *testing.T, rm *RouteManager, want ...string) {
	t.Helper()
	wantSet := make(set.Set[netip.Prefix])
	for _, s := range want {
		wantSet.Add(pfx(s))
	}
	got := make(set.Set[netip.Prefix])
	for p := range rm.OSRoutes().All() {
		got.Add(p)
	}
	if !got.Equal(wantSet) {
		t.Errorf("OSRoutes = %v; want %v", got.Slice(), wantSet.Slice())
	}
}

func TestSelfAddrs(t *testing.T) {
	rm := New(t.Logf)
	res := commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })

	if res.PeersUpserted != 1 {
		t.Errorf("PeersUpserted = %d; want 1", res.PeersUpserted)
	}
	if !res.OutboundChanged || !res.OSRoutesChanged {
		t.Errorf("changed flags = %v/%v; want all true", res.OutboundChanged, res.OSRoutesChanged)
	}
	if res.Outbound == nil || res.OSRoutes == nil {
		t.Error("Result snapshot pointers should be non-nil when changed")
	}

	wantOutbound(t, rm, "100.64.0.1", k1, true)
	wantOutbound(t, rm, "fd7a:115c:a1e0::1", k1, true)
	wantOutbound(t, rm, "100.64.0.2", key.NodePublic{}, false)
	// Individual CGNAT /32 (below threshold) plus the coarse ULA range.
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48")
}

func TestRemovePeer(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })
	res := commit(rm, func(m *Mutation) { m.RemovePeer(1) })

	if res.PeersRemoved != 1 {
		t.Errorf("PeersRemoved = %d; want 1", res.PeersRemoved)
	}
	wantOutbound(t, rm, "100.64.0.1", key.NodePublic{}, false)
	wantOSRoutes(t, rm)
	if rm.ForTest().PeerCount() != 0 {
		t.Errorf("PeerCount = %d; want 0", rm.ForTest().PeerCount())
	}

	// Removing an unknown peer is a no-op.
	res = commit(rm, func(m *Mutation) { m.RemovePeer(42) })
	if res.PeersRemoved != 0 || res.OutboundChanged {
		t.Errorf("remove of unknown peer: %+v", res)
	}
}

func TestExitNodeGating(t *testing.T) {
	rm := New(t.Logf)
	exitPeer := peer1()
	exitPeer.Routes = tsaddr.ExitRoutes()
	commit(rm, func(m *Mutation) { m.upsertPeer(exitPeer) })

	// Not selected: no /0 entries anywhere.
	wantOutbound(t, rm, "8.8.8.8", key.NodePublic{}, false)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48")

	// Select it as exit node.
	res := commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{ExitNodeID: 1}) })
	if !res.PrefsChanged || !res.OutboundChanged || !res.OSRoutesChanged {
		t.Errorf("select exit node: %+v", res)
	}
	wantOutbound(t, rm, "8.8.8.8", k1, true)
	wantOutbound(t, rm, "2001:db8::1", k1, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "0.0.0.0/0", "::/0")

	// Deselect: /0s vanish.
	commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{}) })
	wantOutbound(t, rm, "8.8.8.8", key.NodePublic{}, false)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48")

	// Selecting a peer that doesn't advertise /0s adds nothing.
	commit(rm, func(m *Mutation) {
		m.upsertPeer(peer2())
		m.SetPrefs(Prefs{ExitNodeID: 2})
	})
	wantOutbound(t, rm, "8.8.8.8", key.NodePublic{}, false)
}

func TestRouteAll(t *testing.T) {
	rm := New(t.Logf)
	p := peer1()
	p.Routes = []netip.Prefix{pfx("10.0.0.0/24")}
	commit(rm, func(m *Mutation) { m.upsertPeer(p) })

	// Subnet routes ignored until RouteAll.
	wantOutbound(t, rm, "10.0.0.5", key.NodePublic{}, false)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48")

	commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	wantOutbound(t, rm, "10.0.0.5", k1, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "10.0.0.0/24")

	commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{}) })
	wantOutbound(t, rm, "10.0.0.5", key.NodePublic{}, false)
}

func TestSharedSubnetRoute(t *testing.T) {
	rm := New(t.Logf)
	route := pfx("10.0.0.0/24")
	pa, pb := peer1(), peer2()
	pa.Routes = []netip.Prefix{route}
	pb.Routes = []netip.Prefix{route}
	commit(rm, func(m *Mutation) {
		m.upsertPeer(pa)
		m.upsertPeer(pb)
		m.SetPrefs(Prefs{RouteAll: true})
	})

	// Tie on score: lowest NodeID wins outbound.
	wantOutbound(t, rm, "10.0.0.5", k1, true)

	// Raise peer 2's score: outbound flips, OS routes unchanged.
	res := commit(rm, func(m *Mutation) { m.SetScore(2, route, 100) })
	if res.ScoresChanged != 1 || !res.OutboundChanged || res.OSRoutesChanged {
		t.Errorf("score change: %+v", res)
	}
	wantOutbound(t, rm, "10.0.0.5", k2, true)

	// Setting the same score again is a no-op.
	res = commit(rm, func(m *Mutation) { m.SetScore(2, route, 100) })
	if res.ScoresChanged != 0 || res.OutboundChanged {
		t.Errorf("same score: %+v", res)
	}

	// Resetting the score to zero restores the NodeID tie-break.
	res = commit(rm, func(m *Mutation) { m.SetScore(2, route, 0) })
	if res.ScoresChanged != 1 || !res.OutboundChanged {
		t.Errorf("score reset: %+v", res)
	}
	wantOutbound(t, rm, "10.0.0.5", k1, true)

	// Resetting an already-absent score is a no-op.
	res = commit(rm, func(m *Mutation) { m.SetScore(2, route, 0) })
	if res.ScoresChanged != 0 {
		t.Errorf("absent score reset: %+v", res)
	}

	// Restore peer 2 as winner for the removal test below.
	commit(rm, func(m *Mutation) { m.SetScore(2, route, 100) })
	wantOutbound(t, rm, "10.0.0.5", k2, true)

	// Removing the winner falls back to the other advertiser.
	commit(rm, func(m *Mutation) { m.RemovePeer(2) })
	wantOutbound(t, rm, "10.0.0.5", k1, true)

	// Peer 2's score was dropped on removal: re-adding it ties again
	// and peer 1 wins by lower NodeID.
	commit(rm, func(m *Mutation) { m.upsertPeer(pb) })
	wantOutbound(t, rm, "10.0.0.5", k1, true)
}

func TestOneCGNAT(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) {
		m.SetTailnetConfig(TailnetConfig{OneCGNAT: true})
		m.upsertPeer(peer1())
	})
	// One CGNAT addr: not above threshold (1 > 1 is false), so
	// still individual, mirroring ipnlocal.peerRoutes.
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48")

	// Second CGNAT addr crosses the threshold: collapse to /10.
	res := commit(rm, func(m *Mutation) { m.upsertPeer(peer2()) })
	if !res.OSRoutesChanged {
		t.Errorf("crossing threshold: %+v", res)
	}
	wantOSRoutes(t, rm, "100.64.0.0/10", "fd7a:115c:a1e0::/48")

	// Hot-path tables stay exact regardless of OS coarsening.
	wantOutbound(t, rm, "100.64.0.2", k2, true)
	wantOutbound(t, rm, "100.64.0.3", key.NodePublic{}, false)

	// Dropping back below the threshold un-coarsens.
	commit(rm, func(m *Mutation) { m.RemovePeer(2) })
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48")
}

// TestFullRebuildWhileCoarse exercises the full-rebuild path (a prefs
// change) while CGNAT coarsening is already active.
func TestFullRebuildWhileCoarse(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) {
		m.SetTailnetConfig(TailnetConfig{OneCGNAT: true})
		m.upsertPeer(peer1())
		m.upsertPeer(peer2())
	})
	wantOSRoutes(t, rm, "100.64.0.0/10", "fd7a:115c:a1e0::/48")

	res := commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	if !res.PrefsChanged || res.OSRoutesChanged {
		t.Errorf("prefs change while coarse: %+v", res)
	}
	wantOSRoutes(t, rm, "100.64.0.0/10", "fd7a:115c:a1e0::/48")
	wantOutbound(t, rm, "100.64.0.2", k2, true)
}

// TestSingleIPPlainRoute checks that a single-IP route outside the
// CGNAT and ULA ranges is programmed individually, not coarsened.
func TestSingleIPPlainRoute(t *testing.T) {
	rm := New(t.Logf)
	p := peer1()
	p.Routes = []netip.Prefix{pfx("192.0.2.7/32")}
	commit(rm, func(m *Mutation) {
		m.upsertPeer(p)
		m.SetPrefs(Prefs{RouteAll: true})
	})
	wantOutbound(t, rm, "192.0.2.7", k1, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "192.0.2.7/32")
}

func TestDisableIPv4(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) {
		m.SetTailnetConfig(TailnetConfig{DisableIPv4: true})
		m.upsertPeer(peer1())
	})
	wantOutbound(t, rm, "100.64.0.1", key.NodePublic{}, false)
	wantOutbound(t, rm, "fd7a:115c:a1e0::1", k1, true)
	wantOSRoutes(t, rm, "fd7a:115c:a1e0::/48")
}

func TestKeyRotation(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })

	rotated := peer1()
	rotated.Key = k3
	res := commit(rm, func(m *Mutation) { m.upsertPeer(rotated) })
	if !res.OutboundChanged || res.OSRoutesChanged {
		t.Errorf("key rotation: %+v", res)
	}
	wantOutbound(t, rm, "100.64.0.1", k3, true)
}

// TestPeerRouteAttrs checks that the data-plane attributes (jailed,
// masquerade addresses) are published in the outbound table, that
// changing only an attribute republishes the peer's prefixes, and
// that previously published snapshots keep the old attributes.
func TestPeerRouteAttrs(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })

	pr, ok := rm.Outbound().Lookup(addr("100.64.0.1"))
	if !ok || pr.Jailed || pr.MasqAddr4.IsValid() || pr.MasqAddr6.IsValid() {
		t.Fatalf("initial attrs = %+v, %v; want unjailed, no masq", pr, ok)
	}
	if rm.HasDataPlaneAttrs() {
		t.Error("HasDataPlaneAttrs = true with no jailed or masqueraded peers")
	}
	oldOut := rm.Outbound()

	jailed := peer1()
	jailed.Jailed = true
	jailed.MasqAddr4 = addr("100.99.0.1")
	res := commit(rm, func(m *Mutation) { m.upsertPeer(jailed) })
	if !res.OutboundChanged || res.OSRoutesChanged {
		t.Errorf("attr change: %+v", res)
	}
	if res.AllowedIPs != nil {
		t.Errorf("attr change reported AllowedIPs %v; attrs must not affect allowed prefixes", res.AllowedIPs)
	}
	pr, ok = rm.Outbound().Lookup(addr("100.64.0.1"))
	if !ok || !pr.Jailed || pr.MasqAddr4 != addr("100.99.0.1") || pr.Key != k1 {
		t.Fatalf("updated attrs = %+v, %v", pr, ok)
	}
	if !rm.HasDataPlaneAttrs() {
		t.Error("HasDataPlaneAttrs = false with a jailed peer")
	}
	if pr, ok := oldOut.Lookup(addr("100.64.0.1")); !ok || pr.Jailed {
		t.Errorf("old snapshot attrs = %+v, %v; want original unjailed entry", pr, ok)
	}

	// An identical re-upsert is a no-op.
	res = commit(rm, func(m *Mutation) { m.upsertPeer(jailed) })
	if res.OutboundChanged {
		t.Errorf("identical attrs re-upsert changed outbound: %+v", res)
	}
	if !rm.HasDataPlaneAttrs() {
		t.Error("HasDataPlaneAttrs = false after identical re-upsert of a jailed peer")
	}

	// Removing the peer drops its data-plane attributes.
	commit(rm, func(m *Mutation) { m.RemovePeer(1) })
	if rm.HasDataPlaneAttrs() {
		t.Error("HasDataPlaneAttrs = true after removing the only jailed peer")
	}
}

func TestNoopCommit(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })

	res := commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })
	if res.OutboundChanged || res.OSRoutesChanged {
		t.Errorf("identical re-upsert changed tables: %+v", res)
	}
	if res.Outbound != nil || res.OSRoutes != nil {
		t.Error("Result snapshot pointers should be nil when unchanged")
	}
	if res.PeersUpserted != 1 {
		t.Errorf("PeersUpserted = %d; want 1", res.PeersUpserted)
	}

	// Same prefs again: no rebuild reported.
	commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	res = commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	if res.PrefsChanged {
		t.Errorf("identical prefs reported changed: %+v", res)
	}

	// An empty mutation commits fine.
	res = commit(rm, func(m *Mutation) {})
	if !reflect.DeepEqual(res, Result{}) {
		t.Errorf("empty commit: %+v", res)
	}
}

func TestUnmaskedPrefixSkipped(t *testing.T) {
	rm := New(t.Logf)
	p := peer1()
	p.Routes = []netip.Prefix{netip.PrefixFrom(addr("10.0.0.5"), 24)} // non-address bits set
	commit(rm, func(m *Mutation) {
		m.upsertPeer(p)
		m.SetPrefs(Prefs{RouteAll: true})
	})
	wantOutbound(t, rm, "10.0.0.5", key.NodePublic{}, false)
}

func TestSnapshotImmutability(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })
	oldOut := rm.Outbound()

	commit(rm, func(m *Mutation) { m.RemovePeer(1) })

	// The old snapshot still sees the removed peer.
	if _, ok := oldOut.Lookup(addr("100.64.0.1")); !ok {
		t.Error("old outbound snapshot lost entry after later commit")
	}
	// And the new one doesn't.
	wantOutbound(t, rm, "100.64.0.1", key.NodePublic{}, false)
}

func TestDiscard(t *testing.T) {
	rm := New(t.Logf)
	m := rm.Begin()
	m.upsertPeer(peer1())
	m.Discard()
	if rm.ForTest().PeerCount() != 0 {
		t.Error("discarded mutation was applied")
	}
	// A new mutation works after a discard.
	commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })
	if rm.ForTest().PeerCount() != 1 {
		t.Error("commit after discard failed")
	}
}

func TestConcurrentMutationPanics(t *testing.T) {
	rm := New(t.Logf)
	m1 := rm.Begin()
	m2 := rm.Begin()
	m1.upsertPeer(peer1())
	m1.Commit()

	defer func() {
		if recover() == nil {
			t.Error("overlapping Commit did not panic")
		}
	}()
	m2.Commit()
}

func TestFinishedMutationPanics(t *testing.T) {
	rm := New(t.Logf)
	m := rm.Begin()
	m.Commit()
	defer func() {
		if recover() == nil {
			t.Error("op on finished Mutation did not panic")
		}
	}()
	m.upsertPeer(peer1())
}

func TestPeerModifyRoutes(t *testing.T) {
	rm := New(t.Logf)
	p := peer1()
	p.Routes = []netip.Prefix{pfx("10.0.0.0/24")}
	commit(rm, func(m *Mutation) {
		m.upsertPeer(p)
		m.SetPrefs(Prefs{RouteAll: true})
	})
	wantOutbound(t, rm, "10.0.0.5", k1, true)

	// Swap the advertised route for another.
	p.Routes = []netip.Prefix{pfx("192.168.1.0/24")}
	res := commit(rm, func(m *Mutation) { m.upsertPeer(p) })
	if !res.OutboundChanged {
		t.Errorf("route swap: %+v", res)
	}
	wantOutbound(t, rm, "10.0.0.5", key.NodePublic{}, false)
	wantOutbound(t, rm, "192.168.1.5", k1, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48", "192.168.1.0/24")
}

// BenchmarkUpsertOnePeer measures the cost of a single-peer mutation
// against a manager already tracking many peers, the case the
// incremental design exists for.
func BenchmarkUpsertOnePeer(b *testing.B) {
	rm := New(nil)
	m := rm.Begin()
	for i := range 10_000 {
		id := tailcfg.NodeID(i + 1)
		m.upsertPeer(peerView{
			ID:  id,
			Key: key.NewNode().Public(),
			SelfAddrs: []netip.Prefix{
				netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}), 32),
			},
		})
	}
	m.Commit()

	p := peerView{
		ID:        99_999,
		Key:       key.NewNode().Public(),
		SelfAddrs: []netip.Prefix{pfx("100.100.1.1/32")},
	}
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		p.SelfAddrs[0] = netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 100, byte(i >> 8), byte(i)}), 32)
		m := rm.Begin()
		m.upsertPeer(p)
		m.Commit()
	}
}

func TestUpsertPeerNodeView(t *testing.T) {
	rm := New(t.Logf)
	n := &tailcfg.Node{
		ID:       1,
		Key:      k1,
		HomeDERP: 1,
		Addresses: []netip.Prefix{
			pfx("100.64.0.1/32"),
			pfx("fd7a:115c:a1e0::1/128"),
		},
		AllowedIPs: []netip.Prefix{
			pfx("100.64.0.1/32"),
			pfx("fd7a:115c:a1e0::1/128"),
			pfx("10.0.0.0/24"),
			pfx("0.0.0.0/0"),
			pfx("::/0"),
		},
		IsJailed:                      true,
		SelfNodeV4MasqAddrForThisPeer: new(addr("100.99.0.5")),
	}
	commit(rm, func(m *Mutation) { m.UpsertPeer(n.View()) })

	// The data-plane attributes are carried through from the node.
	if pr, ok := rm.Outbound().Lookup(addr("100.64.0.1")); !ok || !pr.Jailed || pr.MasqAddr4 != addr("100.99.0.5") || pr.MasqAddr6.IsValid() {
		t.Errorf("attrs = %+v, %v; want jailed with v4 masq only", pr, ok)
	}

	// Self addresses are live immediately; the subnet route and the
	// exit routes were classified as routes and stay gated by prefs.
	wantOutbound(t, rm, "100.64.0.1", k1, true)
	wantOutbound(t, rm, "10.0.0.5", key.NodePublic{}, false)
	wantOutbound(t, rm, "8.8.8.8", key.NodePublic{}, false)

	commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true, ExitNodeID: 1}) })
	wantOutbound(t, rm, "10.0.0.5", k1, true)
	wantOutbound(t, rm, "8.8.8.8", k1, true)
}

// TestUpsertPeerNodeViewVIPService checks that a single Tailscale IP
// in a peer's AllowedIPs but not in its Addresses (such as a VIP
// service address hosted by the peer) is classified as a self address
// and stays routable without Prefs.RouteAll, mirroring nmcfg's
// cidrIsSubnet.
func TestUpsertPeerNodeViewVIPService(t *testing.T) {
	rm := New(t.Logf)
	n := &tailcfg.Node{
		ID:       1,
		Key:      k1,
		HomeDERP: 1,
		Addresses: []netip.Prefix{
			pfx("100.64.0.1/32"),
		},
		AllowedIPs: []netip.Prefix{
			pfx("100.64.0.1/32"),
			pfx("100.100.5.5/32"),  // VIP service address
			pfx("192.168.1.99/32"), // single non-Tailscale IP: a subnet route
			pfx("10.0.0.0/24"),
		},
	}
	commit(rm, func(m *Mutation) { m.UpsertPeer(n.View()) })

	// With RouteAll off, the node address and the VIP service address
	// are routable, but the subnet routes are not.
	wantOutbound(t, rm, "100.64.0.1", k1, true)
	wantOutbound(t, rm, "100.100.5.5", k1, true)
	wantOutbound(t, rm, "192.168.1.99", key.NodePublic{}, false)
	wantOutbound(t, rm, "10.0.0.5", key.NodePublic{}, false)
	wantOSRoutes(t, rm, "100.64.0.1/32", "100.100.5.5/32")

	commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	wantOutbound(t, rm, "192.168.1.99", k1, true)
	wantOutbound(t, rm, "10.0.0.5", k1, true)
}

// TestUpsertPeerNodeViewEmptyAllowedIPs checks that AllowedIPs is
// the sole source of prefixes: a peer whose AllowedIPs is empty is
// not routable even if it has addresses, matching nmcfg.WGCfg.
func TestUpsertPeerNodeViewEmptyAllowedIPs(t *testing.T) {
	rm := New(t.Logf)
	n := &tailcfg.Node{
		ID:        1,
		Key:       k1,
		HomeDERP:  1,
		Addresses: []netip.Prefix{pfx("100.64.0.1/32")},
	}
	commit(rm, func(m *Mutation) { m.UpsertPeer(n.View()) })
	wantOutbound(t, rm, "100.64.0.1", key.NodePublic{}, false)
	wantOSRoutes(t, rm)
	if _, ok := rm.PeerAllowedIPs(1); ok {
		t.Error("PeerAllowedIPs = ok; want !ok for peer with no AllowedIPs")
	}
}

// TestUpsertPeerNodeViewIneligible checks that peers we cannot
// communicate with (expired, or predating both DERP and disco) are
// tracked but contribute no prefixes, mirroring nmcfg.WGCfg's peer
// filtering, and that a later update restores them.
func TestUpsertPeerNodeViewIneligible(t *testing.T) {
	base := func() *tailcfg.Node {
		return &tailcfg.Node{
			ID:        1,
			Key:       k1,
			HomeDERP:  1,
			Addresses: []netip.Prefix{pfx("100.64.0.1/32")},
			AllowedIPs: []netip.Prefix{
				pfx("100.64.0.1/32"),
			},
		}
	}

	for _, tc := range []struct {
		name string
		mod  func(*tailcfg.Node)
	}{
		{"expired", func(n *tailcfg.Node) { n.Expired = true }},
		{"noDERPOrDisco", func(n *tailcfg.Node) { n.HomeDERP = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rm := New(t.Logf)
			n := base()
			tc.mod(n)
			commit(rm, func(m *Mutation) { m.UpsertPeer(n.View()) })
			wantOutbound(t, rm, "100.64.0.1", key.NodePublic{}, false)
			wantOSRoutes(t, rm)
			if _, ok := rm.PeerAllowedIPs(1); ok {
				t.Error("PeerAllowedIPs = ok; want !ok for ineligible peer")
			}

			// An update that clears the condition restores the peer.
			commit(rm, func(m *Mutation) { m.UpsertPeer(base().View()) })
			wantOutbound(t, rm, "100.64.0.1", k1, true)
		})
	}
}

// wantChangedAllowedIPs checks res.AllowedIPs against want, where
// want maps each expected key to its expected new prefixes (nil for
// "no allowed prefixes").
func wantChangedAllowedIPs(t *testing.T, res Result, want map[key.NodePublic][]string) {
	t.Helper()
	wantMap := make(map[key.NodePublic][]netip.Prefix)
	for k, ss := range want {
		var pfxs []netip.Prefix
		for _, s := range ss {
			pfxs = append(pfxs, pfx(s))
		}
		tsaddr.SortPrefixes(pfxs)
		wantMap[k] = pfxs
	}
	if len(want) == 0 {
		if res.AllowedIPs != nil {
			t.Errorf("Result.AllowedIPs = %v; want nil", res.AllowedIPs)
		}
		return
	}
	if !reflect.DeepEqual(res.AllowedIPs, wantMap) {
		t.Errorf("Result.AllowedIPs = %v; want %v", res.AllowedIPs, wantMap)
	}
}

func TestResultAllowedIPs(t *testing.T) {
	rm := New(t.Logf)

	// A new peer appears in the map with its prefixes.
	res := commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128"},
	})

	// An identical re-upsert reports nothing.
	res = commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })
	wantChangedAllowedIPs(t, res, nil)

	// Add a second peer advertising a subnet route and the exit
	// routes; with default prefs only its self addresses count.
	p2 := peer2()
	p2.Routes = []netip.Prefix{pfx("10.0.0.0/24"), pfx("0.0.0.0/0"), pfx("::/0")}
	res = commit(rm, func(m *Mutation) { m.upsertPeer(p2) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k2: {"100.64.0.2/32", "fd7a:115c:a1e0::2/128"},
	})

	// RouteAll adds the subnet route to peer 2 only; peer 1 has no
	// routes, so it does not appear.
	res = commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k2: {"100.64.0.2/32", "fd7a:115c:a1e0::2/128", "10.0.0.0/24"},
	})

	// Selecting peer 2 as exit node adds the /0s to it only.
	res = commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true, ExitNodeID: 2}) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k2: {"100.64.0.2/32", "fd7a:115c:a1e0::2/128", "10.0.0.0/24", "0.0.0.0/0", "::/0"},
	})

	// Deselecting removes them again.
	res = commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k2: {"100.64.0.2/32", "fd7a:115c:a1e0::2/128", "10.0.0.0/24"},
	})

	// A score change affects only the outbound winner, not any
	// peer's allowed prefixes.
	res = commit(rm, func(m *Mutation) { m.SetScore(2, pfx("10.0.0.0/24"), 100) })
	wantChangedAllowedIPs(t, res, nil)

	// A key rotation reports the old key with no prefixes and the
	// new key with the peer's prefixes.
	rotated := peer1()
	rotated.Key = k3
	res = commit(rm, func(m *Mutation) { m.upsertPeer(rotated) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: nil,
		k3: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128"},
	})

	// A removed peer reports its key with no prefixes.
	res = commit(rm, func(m *Mutation) { m.RemovePeer(2) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k2: nil,
	})

	// A prefs change combined with an upsert of a brand-new peer in
	// the same commit reports both correctly: peer 1 gains nothing
	// from RouteAll going away (it has no routes), and the new peer
	// appears with its prefixes.
	p4 := peerView{
		ID:        4,
		Key:       key.NewNode().Public(),
		SelfAddrs: []netip.Prefix{pfx("100.64.0.4/32")},
	}
	res = commit(rm, func(m *Mutation) {
		m.SetPrefs(Prefs{})
		m.upsertPeer(p4)
	})
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		p4.Key: {"100.64.0.4/32"},
	})
}

func TestPeerAllowedIPs(t *testing.T) {
	rm := New(t.Logf)
	p := peer1()
	p.Routes = []netip.Prefix{pfx("10.0.0.0/24"), pfx("0.0.0.0/0"), pfx("::/0")}
	commit(rm, func(m *Mutation) { m.upsertPeer(p) })

	wantAllowed := func(want ...string) {
		t.Helper()
		var wantPfxs []netip.Prefix
		for _, s := range want {
			wantPfxs = append(wantPfxs, pfx(s))
		}
		tsaddr.SortPrefixes(wantPfxs)
		got, ok := rm.PeerAllowedIPs(1)
		if len(want) == 0 {
			if ok {
				t.Errorf("PeerAllowedIPs = %v; want !ok", got)
			}
			return
		}
		if !ok || !slices.Equal(got, wantPfxs) {
			t.Errorf("PeerAllowedIPs = %v, %v; want %v", got, ok, wantPfxs)
		}
	}

	// Default prefs: self addresses only.
	wantAllowed("100.64.0.1/32", "fd7a:115c:a1e0::1/128")

	// RouteAll adds the subnet route but not the exit routes.
	commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	wantAllowed("100.64.0.1/32", "fd7a:115c:a1e0::1/128", "10.0.0.0/24")

	// Selecting the peer as exit node adds the /0s.
	commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true, ExitNodeID: 1}) })
	wantAllowed("100.64.0.1/32", "fd7a:115c:a1e0::1/128", "10.0.0.0/24", "0.0.0.0/0", "::/0")

	// Unknown peers report !ok.
	if _, ok := rm.PeerAllowedIPs(42); ok {
		t.Error("PeerAllowedIPs(42) = ok; want !ok")
	}

	// A removed peer reports !ok.
	commit(rm, func(m *Mutation) { m.RemovePeer(1) })
	wantAllowed()
}

func TestExtraAllowedIPs(t *testing.T) {
	rm := New(t.Logf)
	commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })

	// Extras appear in the outbound table and in PeerAllowedIPs,
	// but not in the OS route set, even for prefixes (like the
	// CGNAT one here) whose class would otherwise be coarsened.
	res := commit(rm, func(m *Mutation) {
		m.SetExtraAllowedIPs(map[tailcfg.NodeID][]netip.Prefix{
			1: {pfx("fe80::1234/128"), pfx("100.100.100.100/32")},
		})
	})
	if !res.ExtrasChanged {
		t.Error("ExtrasChanged = false; want true")
	}
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "fe80::1234/128", "100.100.100.100/32"},
	})
	wantOutbound(t, rm, "fe80::1234", k1, true)
	wantOutbound(t, rm, "100.100.100.100", k1, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48")

	// An identical re-set is a no-op.
	res = commit(rm, func(m *Mutation) {
		m.SetExtraAllowedIPs(map[tailcfg.NodeID][]netip.Prefix{
			1: {pfx("fe80::1234/128"), pfx("100.100.100.100/32")},
		})
	})
	if res.ExtrasChanged || res.OutboundChanged || res.AllowedIPs != nil {
		t.Errorf("no-op re-set changed something: %+v", res)
	}

	// Replacing the set drops the old prefixes and adds the new one.
	res = commit(rm, func(m *Mutation) {
		m.SetExtraAllowedIPs(map[tailcfg.NodeID][]netip.Prefix{
			1: {pfx("fe80::5678/128")},
		})
	})
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "fe80::5678/128"},
	})
	wantOutbound(t, rm, "fe80::1234", key.NodePublic{}, false)
	wantOutbound(t, rm, "fe80::5678", k1, true)

	// Clearing the set removes the remaining extra.
	res = commit(rm, func(m *Mutation) { m.SetExtraAllowedIPs(nil) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128"},
	})
	wantOutbound(t, rm, "fe80::5678", key.NodePublic{}, false)
}

func TestExtraAllowedIPsPeerLifecycle(t *testing.T) {
	rm := New(t.Logf)

	// Extras for a peer that doesn't exist yet have no visible
	// effect until the peer is upserted.
	res := commit(rm, func(m *Mutation) {
		m.SetExtraAllowedIPs(map[tailcfg.NodeID][]netip.Prefix{
			1: {pfx("fe80::1234/128")},
		})
	})
	if !res.ExtrasChanged || res.OutboundChanged || res.AllowedIPs != nil {
		t.Errorf("extras for unknown peer: %+v", res)
	}
	wantOutbound(t, rm, "fe80::1234", key.NodePublic{}, false)

	res = commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{
		k1: {"100.64.0.1/32", "fd7a:115c:a1e0::1/128", "fe80::1234/128"},
	})
	wantOutbound(t, rm, "fe80::1234", k1, true)

	// Removing the peer removes its extras from the tables, but the
	// stored entry survives and re-applies if the peer comes back.
	res = commit(rm, func(m *Mutation) { m.RemovePeer(1) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{k1: nil})
	wantOutbound(t, rm, "fe80::1234", key.NodePublic{}, false)

	commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })
	wantOutbound(t, rm, "fe80::1234", k1, true)

	// A non-communicable peer (no addresses or routes) contributes
	// no prefixes at all, including its extras.
	res = commit(rm, func(m *Mutation) { m.upsertPeer(peerView{ID: 1, Key: k1}) })
	wantChangedAllowedIPs(t, res, map[key.NodePublic][]string{k1: nil})
	wantOutbound(t, rm, "fe80::1234", key.NodePublic{}, false)

	// Extras survive a prefs-driven full rebuild.
	commit(rm, func(m *Mutation) { m.upsertPeer(peer1()) })
	commit(rm, func(m *Mutation) { m.SetPrefs(Prefs{RouteAll: true}) })
	wantOutbound(t, rm, "fe80::1234", k1, true)
	wantOSRoutes(t, rm, "100.64.0.1/32", "fd7a:115c:a1e0::/48")
}
