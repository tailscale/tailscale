// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	gcmp "github.com/google/go-cmp/cmp"
	gcmpopts "github.com/google/go-cmp/cmp/cmpopts"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/routecheck"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

func TestReport(t *testing.T) {
	for _, tc := range []struct {
		name  string
		init  bool // true before the netmap has been loaded
		peers []tailcfg.NodeView
		gone  []tailcfg.NodeID // cannot ping these nodes
		want  []tailcfg.NodeID // Report.Reachable nodes
	}{
		{
			name: "before-netmap",
			init: true,
			want: nil,
		},
		{
			name:  "no-peers",
			peers: []tailcfg.NodeView{},
			want:  []tailcfg.NodeID{},
		},
		{
			name: "no-routers",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
			},
			want: []tailcfg.NodeID{},
		},
		{
			name: "no-choice",
			peers: []tailcfg.NodeView{
				makeNode(11, withName("exit11"), withExitRoutes()),
				makeNode(21, withName("subnet21"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
			},
			want: []tailcfg.NodeID{},
		},
		{
			name: "all-good",
			peers: []tailcfg.NodeView{
				makeNode(11, withName("exit11"), withExitRoutes()),
				makeNode(12, withName("exit12"), withExitRoutes()),
				makeNode(21, withName("subnet21"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
				makeNode(22, withName("subnet22"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
			},
			want: []tailcfg.NodeID{11, 12, 21, 22},
		},
		{
			name: "none-good",
			peers: []tailcfg.NodeView{
				makeNode(11, withName("exit11"), withExitRoutes()),
				makeNode(12, withName("exit12"), withExitRoutes()),
				makeNode(21, withName("subnet21"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
				makeNode(22, withName("subnet22"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
			},
			gone: []tailcfg.NodeID{11, 12, 21, 22},
			want: []tailcfg.NodeID{},
		},
		{
			name: "some-good",
			peers: []tailcfg.NodeView{
				makeNode(11, withName("exit11"), withExitRoutes()),
				makeNode(12, withName("exit12"), withExitRoutes()),
				makeNode(21, withName("subnet21"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
				makeNode(22, withName("subnet22"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
			},
			gone: []tailcfg.NodeID{11, 22},
			want: []tailcfg.NodeID{12, 21},
		},
	} {
		makeDB := func(nodes []tailcfg.NodeView) map[tailcfg.NodeID]routecheck.Node {
			if len(nodes) == 0 {
				return nil
			}
			db := make(map[tailcfg.NodeID]routecheck.Node)
			for _, n := range tc.peers {
				db[n.ID()] = routecheck.Node{
					ID:     n.ID(),
					Name:   n.Name(),
					Addr:   n.Addresses().At(0).Addr(),
					Routes: n.AllowedIPs().AsSlice()[2:],
				}
			}
			return db
		}
		cmpDiff := func(want, got interface{}) string {
			return gcmp.Diff(want, got,
				gcmpopts.EquateComparable(netip.Addr{}, netip.Prefix{}))
		}

		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// The backend is initialized without a NetMap.
				b := newStubBackend(tailcfg.NodeView{}, nil, withGone(tc.gone...))
				if !tc.init {
					self := makeNode(99, withName("self"))
					b = newStubBackend(self, tc.peers, withGone(tc.gone...))
				}
				c, err := routecheck.NewClient(t.Logf, b, b, b)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				got := c.Report()
				now := time.Now() // synctest will freeze time.

				var want *routecheck.Report
				peers := makeDB(tc.peers)
				if !tc.init {
					want = &routecheck.Report{
						Done: now,
					}
					for _, nid := range tc.want {
						mak.Set(&want.Reachable, nid, peers[nid])
					}
				}

				if diff := cmpDiff(want, got); diff != "" {
					t.Errorf("-want +got:\n%s", diff)
				}
			})
		})
	}
}

func TestRoutersByPrefix(t *testing.T) {
	type routersByPrefix map[netip.Prefix][]tailcfg.NodeID
	simplify := func(rs routecheck.RoutersByPrefix) routersByPrefix {
		out := make(routersByPrefix, len(rs))
		for p, ns := range rs {
			for _, n := range ns {
				out[p] = append(out[p], n.ID())
			}
			slices.Sort(out[p])
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		peers []tailcfg.NodeView
		want  routersByPrefix
	}{
		{
			name:  "no-peers",
			peers: []tailcfg.NodeView{},
			want:  routersByPrefix{},
		},
		{
			name: "no-routers",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
			},
			want: routersByPrefix{},
		},
		{
			name: "one-exit-node",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
				makeNode(11, withName("exit11"), withExitRoutes()),
			},
			want: routersByPrefix{
				netip.MustParsePrefix("0.0.0.0/0"): {11},
				netip.MustParsePrefix("::/0"):      {11},
			},
		},
		{
			name: "overlapping-exit-nodes",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
				makeNode(11, withName("exit11"), withExitRoutes()),
				makeNode(12, withName("exit12"), withExitRoutes()),
			},
			want: routersByPrefix{
				netip.MustParsePrefix("0.0.0.0/0"): {11, 12},
				netip.MustParsePrefix("::/0"):      {11, 12},
			},
		},
		{
			name: "one-subnet-router",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
				makeNode(21, withName("subnet21"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
			},
			want: routersByPrefix{
				netip.MustParsePrefix("192.168.1.0/24"):      {21},
				netip.MustParsePrefix("2002:c000:0100::/48"): {21},
			},
		},
		{
			name: "overlapping-subnet-routers",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
				makeNode(21, withName("subnet21"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
				makeNode(22, withName("subnet22"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
			},
			want: routersByPrefix{
				netip.MustParsePrefix("192.168.1.0/24"):      {21, 22},
				netip.MustParsePrefix("2002:c000:0100::/48"): {21, 22},
			},
		},
		{
			name: "disjoint-subnet-routers",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
				makeNode(21, withName("subnet21"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48"))),
				makeNode(22, withName("subnet22"),
					withRoutes(netip.MustParsePrefix("192.168.2.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0200::/48"))),
			},
			want: routersByPrefix{
				netip.MustParsePrefix("192.168.1.0/24"):      {21},
				netip.MustParsePrefix("2002:c000:0100::/48"): {21},
				netip.MustParsePrefix("192.168.2.0/24"):      {22},
				netip.MustParsePrefix("2002:c000:0200::/48"): {22},
			},
		},
		{
			name: "multiple-routes",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
				makeNode(21, withName("subnet21"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48")),
					withRoutes(netip.MustParsePrefix("192.168.2.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0200::/48"))),
				makeNode(22, withName("subnet22"),
					withRoutes(netip.MustParsePrefix("192.168.2.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0200::/48")),
					withRoutes(netip.MustParsePrefix("192.168.3.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0300::/48"))),
				makeNode(23, withName("subnet23"),
					withRoutes(netip.MustParsePrefix("192.168.3.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0300::/48")),
					withRoutes(netip.MustParsePrefix("192.168.4.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0400::/48"))),
			},
			want: routersByPrefix{
				netip.MustParsePrefix("192.168.1.0/24"):      {21},
				netip.MustParsePrefix("2002:c000:0100::/48"): {21},
				netip.MustParsePrefix("192.168.2.0/24"):      {21, 22},
				netip.MustParsePrefix("2002:c000:0200::/48"): {21, 22},
				netip.MustParsePrefix("192.168.3.0/24"):      {22, 23},
				netip.MustParsePrefix("2002:c000:0300::/48"): {22, 23},
				netip.MustParsePrefix("192.168.4.0/24"):      {23},
				netip.MustParsePrefix("2002:c000:0400::/48"): {23},
			},
		},
		{
			name: "both-exit-nodes-and-routers",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
				makeNode(11, withName("exit11"), withExitRoutes()),
				makeNode(12, withName("exit12"), withExitRoutes()),
				makeNode(21, withName("subnet21"),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48")),
					withRoutes(netip.MustParsePrefix("192.168.2.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0200::/48"))),
				makeNode(22, withName("subnet22"),
					withRoutes(netip.MustParsePrefix("192.168.2.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0200::/48")),
					withRoutes(netip.MustParsePrefix("192.168.3.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0300::/48"))),
			},
			want: routersByPrefix{
				netip.MustParsePrefix("0.0.0.0/0"):           {11, 12},
				netip.MustParsePrefix("::/0"):                {11, 12},
				netip.MustParsePrefix("192.168.1.0/24"):      {21},
				netip.MustParsePrefix("2002:c000:0100::/48"): {21},
				netip.MustParsePrefix("192.168.2.0/24"):      {21, 22},
				netip.MustParsePrefix("2002:c000:0200::/48"): {21, 22},
				netip.MustParsePrefix("192.168.3.0/24"):      {22},
				netip.MustParsePrefix("2002:c000:0300::/48"): {22},
			},
		},
		{
			name: "mixed-nodes",
			peers: []tailcfg.NodeView{
				makeNode(1, withName("peer1")),
				makeNode(31, withName("router31"),
					withExitRoutes(),
					withRoutes(netip.MustParsePrefix("192.168.1.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0100::/48")),
					withRoutes(netip.MustParsePrefix("192.168.2.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0200::/48"))),
				makeNode(32, withName("router32"),
					withExitRoutes(),
					withRoutes(netip.MustParsePrefix("192.168.2.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0200::/48")),
					withRoutes(netip.MustParsePrefix("192.168.3.0/24")),
					withRoutes(netip.MustParsePrefix("2002:c000:0300::/48"))),
			},
			want: routersByPrefix{
				netip.MustParsePrefix("0.0.0.0/0"):           {31, 32},
				netip.MustParsePrefix("::/0"):                {31, 32},
				netip.MustParsePrefix("192.168.1.0/24"):      {31},
				netip.MustParsePrefix("2002:c000:0100::/48"): {31},
				netip.MustParsePrefix("192.168.2.0/24"):      {31, 32},
				netip.MustParsePrefix("2002:c000:0200::/48"): {31, 32},
				netip.MustParsePrefix("192.168.3.0/24"):      {32},
				netip.MustParsePrefix("2002:c000:0300::/48"): {32},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			self := makeNode(99, withName("self"))
			b := newStubBackend(self, tc.peers)
			c, err := routecheck.NewClient(t.Logf, b, b, b)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got := simplify(c.RoutersByPrefix())
			if !maps.EqualFunc(got, tc.want, slices.Equal) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}

}

type nodeOptFunc func(*tailcfg.Node)

func makeNode(id tailcfg.NodeID, opts ...nodeOptFunc) tailcfg.NodeView {
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
	return node.View()
}

func withExitRoutes() nodeOptFunc {
	return withRoutes(tsaddr.ExitRoutes()...)
}

func withName(name string) nodeOptFunc {
	return func(n *tailcfg.Node) {
		n.Name = name
	}
}

func withRoutes(routes ...netip.Prefix) nodeOptFunc {
	return func(n *tailcfg.Node) {
		n.AllowedIPs = append(n.AllowedIPs, routes...)
	}
}

var _ routecheck.NodeBackender = &stubBackend{}
var _ routecheck.NodeBackend = &stubBackend{}
var _ routecheck.NetMapWaiter = &stubBackend{}
var _ routecheck.Pinger = &stubBackend{}

type stubBackend struct {
	self  tailcfg.NodeView
	peers []tailcfg.NodeView
	gone  set.Set[tailcfg.NodeID]
}

type backendOptFunc func(*stubBackend)

func newStubBackend(self tailcfg.NodeView, peers []tailcfg.NodeView, opts ...backendOptFunc) *stubBackend {
	b := &stubBackend{
		self:  self,
		peers: slices.Clone(peers),
	}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

func (b *stubBackend) NetMap() *netmap.NetworkMap {
	if !b.self.Valid() {
		return nil
	}
	return &netmap.NetworkMap{
		SelfNode: b.self,
		Peers:    b.peers,
	}
}

func (b *stubBackend) WaitForNetMap(ctx context.Context) (*netmap.NetworkMap, error) {
	nm := b.NetMap()
	if nm == nil {
		<-ctx.Done()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("no netmap to wait for")
	}
	return nm, nil
}

func (nb *stubBackend) NodeBackend() routecheck.NodeBackend {
	return nb
}

func (nb *stubBackend) Self() tailcfg.NodeView {
	return nb.self
}

func (nb *stubBackend) Peers() []tailcfg.NodeView {
	return nb.peers
}

func (b *stubBackend) Ping(ip netip.Addr, pingType tailcfg.PingType, size int, cb func(*ipnstate.PingResult)) {
	// Does the IP address match one of the peers’ addresses?
	for _, n := range b.peers {
		for _, a := range n.Addresses().All() {
			if a.Addr() != ip {
				continue
			}

			if b.gone.Contains(n.ID()) {
				continue
			}

			go cb(&ipnstate.PingResult{
				IP:             ip.String(),
				NodeIP:         ip.String(),
				NodeName:       n.Name(),
				LatencySeconds: 0.01,
			})
		}
	}
}

func withGone(gone ...tailcfg.NodeID) backendOptFunc {
	return func(b *stubBackend) {
		b.gone = set.SetOf(gone)
	}

}
