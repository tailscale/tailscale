// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"

	gcmp "github.com/google/go-cmp/cmp"

	"tailscale.com/feature/routecheck"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	netroutecheck "tailscale.com/net/routecheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

func TestRouterTracker(t *testing.T) {
	self := makeSelfNodeWithRouteCheckEnabled(t)

	for _, tc := range []struct {
		name         string
		bus          ipnBus
		wantAdded    []tailcfg.NodeID
		wantModified []tailcfg.NodeID
		wantRemoved  []tailcfg.NodeID
	}{
		{
			name:         "initial",
			bus:          ipnBus{},
			wantAdded:    nil,
			wantModified: nil,
			wantRemoved:  nil,
		},
		{
			name: "added",
			bus: ipnBus{
				{PeersChanged: []*tailcfg.Node{makeNode(1, withRoutes(netip.MustParsePrefix("192.168.1.0/24")))}},
			},
			wantAdded:    []tailcfg.NodeID{1},
			wantModified: nil,
			wantRemoved:  nil,
		},
		{
			name: "modified",
			bus: ipnBus{
				{PeersChanged: []*tailcfg.Node{makeNode(2, withRoutes(netip.MustParsePrefix("192.168.1.0/24")))}},

				{PeersChanged: []*tailcfg.Node{makeNode(2, withRoutes(netip.MustParsePrefix("192.168.2.0/24")))}},
			},
			wantAdded:    nil,
			wantModified: []tailcfg.NodeID{2},
			wantRemoved:  nil,
		},
		{
			name: "removed",
			bus: ipnBus{
				{PeersChanged: []*tailcfg.Node{makeNode(3, withRoutes(netip.MustParsePrefix("192.168.3.0/24")))}},
				{PeersRemoved: []tailcfg.NodeID{3}},
			},
			wantAdded:    nil,
			wantModified: nil,
			wantRemoved:  []tailcfg.NodeID{3},
		},
		{
			name: "removed-already",
			bus: ipnBus{
				{PeersRemoved: []tailcfg.NodeID{3}},
			},
			wantAdded:    nil,
			wantModified: nil,
			wantRemoved:  nil,
		},
		{
			name: "plain-node",
			bus: ipnBus{
				{PeersChanged: []*tailcfg.Node{makeNode(4)}},

				{PeersChanged: []*tailcfg.Node{makeNode(4)}},
			},
			wantAdded:    nil,
			wantModified: nil,
			wantRemoved:  nil,
		},
		{
			name: "authorized",
			bus: ipnBus{
				{PeersChanged: []*tailcfg.Node{makeNode(5)}},

				{PeersChanged: []*tailcfg.Node{makeNode(5, withRoutes(netip.MustParsePrefix("192.168.5.0/24")))}},
			},
			wantAdded:    []tailcfg.NodeID{5},
			wantModified: nil,
			wantRemoved:  nil,
		},
		{
			name: "unauthorized",
			bus: ipnBus{
				{PeersChanged: []*tailcfg.Node{makeNode(6, withRoutes(netip.MustParsePrefix("192.168.6.0/24")))}},

				{PeersChanged: []*tailcfg.Node{makeNode(6)}},
			},
			wantAdded:    nil,
			wantModified: nil,
			wantRemoved:  []tailcfg.NodeID{6},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var gotAdded, gotModified, gotRemoved []tailcfg.NodeID
				rt := routecheck.TrackRouters(t.Context(), t.Logf, &tc.bus)
				rt.OnRoutersChange = func(added, modified, removed []tailcfg.NodeID) {
					gotAdded, gotModified, gotRemoved = added, modified, removed
				}
				defer rt.Close()

				if started, err := rt.StartStopWatcher(self); err != nil {
					t.Fatalf("error starting watcher: %v", err)
				} else if !started {
					t.Fatalf("failed to start watcher")
				}

				synctest.Wait()
				if diff := gcmp.Diff(tc.wantAdded, gotAdded); diff != "" {
					t.Errorf("mismatched added: -want, +got:\n%s", diff)
				}
				if diff := gcmp.Diff(tc.wantModified, gotModified); diff != "" {
					t.Errorf("mismatched modified: -want, +got:\n%s", diff)
				}
				if diff := gcmp.Diff(tc.wantRemoved, gotRemoved); diff != "" {
					t.Errorf("mismatched removed: -want, +got:\n%s", diff)
				}
			})
		})
	}
}

func TestRouterTrackerRaisesOnNetMapAvailable(t *testing.T) {
	self := makeSelfNodeWithRouteCheckEnabled(t)
	routers := []*tailcfg.Node{makeNode(1, withRoutes(netip.MustParsePrefix("192.168.1.0/24")))}

	for _, tc := range []struct {
		name string
		bus  ipnBus
		want opt.Bool
	}{
		{
			name: "empty",
			bus:  ipnBus{},
			want: opt.ExplicitlyUnset,
		},
		{
			name: "initial-status",
			bus: ipnBus{
				{
					InitialStatus: &ipnstate.Status{},
					PeersChanged:  routers,
				},
			},
			want: opt.True,
		},
		{
			name: "no-initial-status",
			bus: ipnBus{
				{
					InitialStatus: nil,
					PeersChanged:  routers,
				},
			},
			want: opt.False,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				got := opt.ExplicitlyUnset
				rt := routecheck.TrackRouters(t.Context(), t.Logf, &tc.bus)
				rt.OnNetMapAvailable = func() {
					t.Logf("OnNetMapAvailable")
					got = opt.True
				}
				rt.OnRoutersChange = func(_, _, _ []tailcfg.NodeID) {
					t.Logf("OnRoutersChange")
					if got == opt.ExplicitlyUnset {
						got = opt.False
					}
				}
				defer rt.Close()

				if started, err := rt.StartStopWatcher(self); err != nil {
					t.Fatalf("error starting watcher: %v", err)
				} else if !started {
					t.Fatalf("failed to start watcher")
				}

				synctest.Wait()
				if got != tc.want {
					t.Errorf("got %v, want %v", got, tc.want)
				}
			})
		})
	}
}

func makeSelfNodeWithRouteCheckEnabled(t *testing.T) tailcfg.NodeView {
	t.Helper()
	self := (&tailcfg.Node{
		CapMap: tailcfg.NodeCapMap{
			tailcfg.NodeAttrClientSideReachability:           nil,
			tailcfg.NodeAttrClientSideReachabilityRouteCheck: nil,
		},
	}).View()
	if !netroutecheck.IsEnabled(self) {
		t.Fatalf("routecheck not enabled for self node: %v", self)
	}
	return self
}

type ipnBus []ipn.Notify

func (b *ipnBus) WatchNotifications(ctx context.Context, mask ipn.NotifyWatchOpt, onWatchAdded func(), fn func(roNotify *ipn.Notify) (keepGoing bool)) {
	if ctx.Err() != nil {
		return
	}
	if onWatchAdded != nil {
		onWatchAdded()
	}
	for _, n := range *b {
		if !fn(&n) {
			return
		}
	}

}

type nodeOptFunc func(*tailcfg.Node)

func makeNode(id tailcfg.NodeID, opts ...nodeOptFunc) *tailcfg.Node {
	addresses := []netip.Prefix{
		netip.MustParsePrefix(fmt.Sprintf("192.168.0.%d/32", id)),
		netip.MustParsePrefix(fmt.Sprintf("fd7a:115c:a1e0::%d/128", id)),
	}
	node := &tailcfg.Node{
		ID:                id,
		StableID:          tailcfg.StableNodeID(fmt.Sprintf("stable%d", id)),
		Name:              fmt.Sprintf("node%d", id),
		Online:            new(true),
		MachineAuthorized: true,
		HomeDERP:          int(id),
		Addresses:         addresses,
		AllowedIPs:        addresses,
	}
	for _, opt := range opts {
		opt(node)
	}
	return node
}

func withRoutes(routes ...netip.Prefix) nodeOptFunc {
	return func(n *tailcfg.Node) {
		n.AllowedIPs = append(n.AllowedIPs, routes...)
	}
}
