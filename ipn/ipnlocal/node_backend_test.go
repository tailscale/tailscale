// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"tailscale.com/net/routecheck/peernode"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

func TestNodeBackendReadiness(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

	// The node backend is not ready until [nodeBackend.ready] is called,
	// and [nodeBackend.Wait] should fail with [context.DeadlineExceeded].
	ctx, cancelCtx := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelCtx()
	if err := nb.Wait(ctx); err != ctx.Err() {
		t.Fatalf("Wait: got %v; want %v", err, ctx.Err())
	}

	// Start a goroutine to wait for the node backend to become ready.
	waitDone := make(chan struct{})
	go func() {
		if err := nb.Wait(context.Background()); err != nil {
			t.Errorf("Wait: got %v; want nil", err)
		}
		close(waitDone)
	}()

	// Call [nodeBackend.ready] to indicate that the node backend is now ready.
	go nb.ready()

	// Once the backend is called, [nodeBackend.Wait] should return immediately without error.
	if err := nb.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: got %v; want nil", err)
	}
	// And any pending waiters should also be unblocked.
	<-waitDone
}

func TestNodeBackendShutdown(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

	shutdownCause := errors.New("test shutdown")

	// Start a goroutine to wait for the node backend to become ready.
	// This test expects it to block until the node backend shuts down
	// and then return the specified shutdown cause.
	waitDone := make(chan struct{})
	go func() {
		if err := nb.Wait(context.Background()); err != shutdownCause {
			t.Errorf("Wait: got %v; want %v", err, shutdownCause)
		}
		close(waitDone)
	}()

	// Call [nodeBackend.shutdown] to indicate that the node backend is shutting down.
	nb.shutdown(shutdownCause)

	// Calling it again is fine, but should not change the shutdown cause.
	nb.shutdown(errors.New("test shutdown again"))

	// After shutdown, [nodeBackend.Wait] should return with the specified shutdown cause.
	if err := nb.Wait(context.Background()); err != shutdownCause {
		t.Fatalf("Wait: got %v; want %v", err, shutdownCause)
	}
	// The context associated with the node backend should also be cancelled
	// and its cancellation cause should match the shutdown cause.
	if err := nb.Context().Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Context.Err: got %v; want %v", err, context.Canceled)
	}
	if cause := context.Cause(nb.Context()); cause != shutdownCause {
		t.Fatalf("Cause: got %v; want %v", cause, shutdownCause)
	}
	// And any pending waiters should also be unblocked.
	<-waitDone
}

func TestNodeBackendReadyAfterShutdown(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

	shutdownCause := errors.New("test shutdown")
	nb.shutdown(shutdownCause)
	nb.ready() // Calling ready after shutdown is a no-op, but should not panic, etc.
	if err := nb.Wait(context.Background()); err != shutdownCause {
		t.Fatalf("Wait: got %v; want %v", err, shutdownCause)
	}
}

func TestNodeBackendParentContextCancellation(t *testing.T) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	nb := newNodeBackend(ctx, tstest.WhileTestRunningLogger(t), eventbus.New())

	cancelCtx()

	// Cancelling the parent context should cause [nodeBackend.Wait]
	// to return with [context.Canceled].
	if err := nb.Wait(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait: got %v; want %v", err, context.Canceled)
	}

	// And the node backend's context should also be cancelled.
	if err := nb.Context().Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Context.Err: got %v; want %v", err, context.Canceled)
	}
}

func TestNodeBackendConcurrentReadyAndShutdown(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

	// Calling [nodeBackend.ready] and [nodeBackend.shutdown] concurrently
	// should not cause issues, and [nodeBackend.Wait] should unblock,
	// but the result of [nodeBackend.Wait] is intentionally undefined.
	go nb.ready()
	go nb.shutdown(errors.New("test shutdown"))

	nb.Wait(context.Background())
}

func TestNodeBackendReachability(t *testing.T) {
	for _, tc := range []struct {
		name string

		// Cap sets [tailcfg.NodeAttrClientSideReachability] on the self
		// node.
		//
		// When disabled, the client relies on the control plane sending
		// an accurate peer.Online flag. When enabled, the client
		// ignores peer.Online and is forced to return true.
		cap bool
		// rchk sets [tailcfg.NodeAttrClientSideReachabilityRouteCheck]
		// on the self node.
		//
		// When enabled with [tailcfg.NodeAttrClientSideReachability]
		// above, the client ignores peer.Online and determines whether
		// it can reach the peer node using [routecheck] reports.
		rchk bool

		online bool
		pong   peernode.Reachability
		want   bool
	}{
		{
			name:   "disabled/offline",
			cap:    false,
			online: false,
			want:   false,
		},
		{
			name:   "disabled/online",
			cap:    false,
			online: true,
			want:   true,
		},
		{
			name:   "forced/offline",
			cap:    true,
			rchk:   false,
			online: false,
			want:   true,
		},
		{
			name:   "forced/online",
			cap:    true,
			rchk:   false,
			online: true,
			want:   true,
		},
		{
			name:   "routecheck/offline/needs-probe",
			cap:    true,
			rchk:   true,
			online: false,
			pong:   peernode.Unknown,
			want:   false,
		},
		{
			name:   "routecheck/offline/unreachable",
			cap:    true,
			rchk:   true,
			online: false,
			pong:   peernode.Unreachable,
			want:   false,
		},
		{
			name:   "routecheck/offline/reachable",
			cap:    true,
			rchk:   true,
			online: false,
			pong:   peernode.Reachable,
			want:   true,
		},
		{
			name:   "routecheck/online/needs-probe",
			cap:    true,
			rchk:   true,
			online: true,
			pong:   peernode.Unknown,
			want:   true,
		},
		{
			name:   "routecheck/online/unreachable",
			cap:    true,
			rchk:   true,
			online: true,
			pong:   peernode.Unreachable,
			want:   false,
		},
		{
			name:   "routecheck/online/reachable",
			cap:    true,
			rchk:   true,
			online: true,
			pong:   peernode.Reachable,
			want:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			self := &tailcfg.Node{
				ID:       1,
				StableID: "stable1",
				Name:     "self",
			}
			if tc.cap {
				mak.Set(&self.CapMap, tailcfg.NodeAttrClientSideReachability, nil)
			}
			if tc.rchk {
				mak.Set(&self.CapMap, tailcfg.NodeAttrClientSideReachabilityRouteCheck, nil)
			}

			peer := &tailcfg.Node{
				ID:       2,
				StableID: "stable2",
				Name:     "peer",
				Online:   &tc.online,
			}

			nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())
			nb.netMap = &netmap.NetworkMap{
				SelfNode: self.View(),
				Peers:    []tailcfg.NodeView{peer.View()},
				// HACK: AllCaps is usually populated by Control
				AllCaps: set.SetOf(slices.Collect(maps.Keys(self.CapMap))),
			}

			got := nb.PeerIsReachable(routecheckReport(tc.pong), peer.View())
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

type routecheckReport peernode.Reachability

var _ RouteCheckReport = *new(routecheckReport)

func (rp routecheckReport) IsReachable(_ tailcfg.NodeID) peernode.Reachability {
	return peernode.Reachability(rp)
}

func TestNodeBackendRouteManager(t *testing.T) {
	nb := newNodeBackend(t.Context(), tstest.WhileTestRunningLogger(t), eventbus.New())

	mkPeer := func(id tailcfg.NodeID, stableID tailcfg.StableNodeID, addr4 string, extra ...string) tailcfg.NodeView {
		n := &tailcfg.Node{
			ID:       id,
			StableID: stableID,
			Key:      key.NewNode().Public(),
			HomeDERP: 1, // required by the route manager's reachability filter
			Addresses: []netip.Prefix{
				netip.MustParsePrefix(addr4),
			},
		}
		n.AllowedIPs = append(n.AllowedIPs, n.Addresses...)
		for _, s := range extra {
			n.AllowedIPs = append(n.AllowedIPs, netip.MustParsePrefix(s))
		}
		return n.View()
	}
	wantPeerFor := func(ip string, want tailcfg.NodeView) {
		t.Helper()
		got, ok := nb.routeMgr.Outbound().Lookup(netip.MustParseAddr(ip))
		if !want.Valid() {
			if ok {
				t.Errorf("Outbound lookup %s = %v; want no match", ip, got)
			}
			return
		}
		if !ok || got.Key != want.Key() {
			t.Errorf("Outbound lookup %s = %v, %v; want %v", ip, got, ok, want.Key())
		}
	}

	p1 := mkPeer(1, "stable1", "100.64.0.1/32")
	p2 := mkPeer(2, "stable2", "100.64.0.2/32", "0.0.0.0/0", "::/0")

	// A full netmap populates the route manager.
	nb.SetNetMap(&netmap.NetworkMap{Peers: []tailcfg.NodeView{p1, p2}})
	wantPeerFor("100.64.0.1", p1)
	wantPeerFor("100.64.0.2", p2)
	wantPeerFor("8.8.8.8", tailcfg.NodeView{}) // exit node not selected

	// Selecting peer 2 as the exit node resolves its stable ID and
	// installs its /0 routes. The commit reports peer 2's allowed
	// prefixes as changed.
	if changed := nb.updateRouteManagerPrefs(routePrefs{ExitNodeID: "stable2", ExitNodeSelected: true}); len(changed) != 1 || changed[p2.Key()] == nil {
		t.Errorf("updateRouteManagerPrefs(exit=stable2) changed = %v; want just %v", changed, p2.Key())
	}
	wantPeerFor("8.8.8.8", p2)

	// A selected exit node that resolves to no current peer must
	// blackhole internet traffic, not fall back to "no exit node":
	// the default routes stay in the OS route set with no outbound
	// peer to carry them. Peer 2's allowed prefixes lose the /0s,
	// which the commit reports.
	if changed := nb.updateRouteManagerPrefs(routePrefs{ExitNodeID: "no-such-node", ExitNodeSelected: true}); len(changed) != 1 || changed[p2.Key()] == nil {
		t.Errorf("updateRouteManagerPrefs(exit=unresolved) changed = %v; want just %v", changed, p2.Key())
	}
	wantPeerFor("8.8.8.8", tailcfg.NodeView{})
	if !nb.routeMgr.OSRoutes().Get(netip.MustParsePrefix("0.0.0.0/0")) {
		t.Error("unresolved exit node: OSRoutes missing 0.0.0.0/0 blackhole route")
	}

	nb.updateRouteManagerPrefs(routePrefs{})
	wantPeerFor("8.8.8.8", tailcfg.NodeView{})
	if nb.routeMgr.OSRoutes().Get(netip.MustParsePrefix("0.0.0.0/0")) {
		t.Error("no exit node: OSRoutes unexpectedly contains 0.0.0.0/0")
	}

	// Incremental deltas: add peer 3, remove peer 1.
	p3 := mkPeer(3, "stable3", "100.64.0.3/32")
	changed, handled := nb.UpdateNetmapDelta([]netmap.NodeMutation{
		netmap.NodeMutationUpsert{Node: p3},
		netmap.MakeNodeMutationRemove(1),
	})
	if !handled {
		t.Fatal("UpdateNetmapDelta not handled")
	}
	if len(changed) != 2 || changed[p3.Key()] == nil {
		t.Errorf("UpdateNetmapDelta changed = %v; want entries for %v and %v", changed, p3.Key(), p1.Key())
	}
	if v, ok := changed[p1.Key()]; !ok || v != nil {
		t.Errorf("UpdateNetmapDelta changed[%v] = %v, %v; want nil, true for removed peer", p1.Key(), v, ok)
	}
	wantPeerFor("100.64.0.3", p3)
	wantPeerFor("100.64.0.1", tailcfg.NodeView{})

	// A full netmap that drops a peer removes it from the route manager.
	nb.SetNetMap(&netmap.NetworkMap{Peers: []tailcfg.NodeView{p2}})
	wantPeerFor("100.64.0.3", tailcfg.NodeView{})
	wantPeerFor("100.64.0.2", p2)
}
