// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/must"
	"tailscale.com/wgengine/filter"
)

// waitFor blocks until a NetMap is seen on the IPN bus that satisfies the given
// function f. Note: has no timeout, should be called with a ctx that has an
// appropriate timeout set.
func waitFor(t testing.TB, ctx context.Context, s *Server, f func(*netmap.NetworkMap) bool) error {
	t.Helper()
	watcher, err := s.localClient.WatchIPNBus(ctx, ipn.NotifyInitialNetMap)
	if err != nil {
		t.Fatalf("error watching IPN bus: %s", err)
	}
	defer watcher.Close()

	for {
		n, err := watcher.Next()
		if err != nil {
			return fmt.Errorf("getting next ipn.Notify from IPN bus: %w", err)
		}
		if n.NetMap != nil {
			if f(n.NetMap) {
				return nil
			}
		}
	}
}

// TestPacketFilterFromNetmap tests all of the client code for processing
// netmaps and turning them into packet filters together. Only the control-plane
// side is mocked out.
func TestPacketFilterFromNetmap(t *testing.T) {
	tstest.Shard(t)
	t.Parallel()

	var key key.NodePublic
	must.Do(key.UnmarshalText([]byte("nodekey:5c8f86d5fc70d924e55f02446165a5dae8f822994ad26bcf4b08fd841f9bf261")))

	type check struct {
		src  string
		dst  string
		port uint16
		want filter.Response
	}

	tests := []struct {
		name        string
		mapResponse *tailcfg.MapResponse
		waitTest    func(*netmap.NetworkMap) bool

		incrementalMapResponse *tailcfg.MapResponse          // optional
		incrementalWaitTest    func(*netmap.NetworkMap) bool // optional

		checks []check
	}{
		{
			name: "IP_based_peers",
			mapResponse: &tailcfg.MapResponse{
				Node: &tailcfg.Node{
					Addresses: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
				},
				Peers: []*tailcfg.Node{{
					ID:        2,
					Name:      "foo",
					Key:       key,
					Addresses: []netip.Prefix{netip.MustParsePrefix("2.2.2.2/32")},
					CapMap:    nil,
				}},
				PacketFilter: []tailcfg.FilterRule{{
					SrcIPs: []string{"2.2.2.2/32"},
					DstPorts: []tailcfg.NetPortRange{{
						IP: "1.1.1.1/32",
						Ports: tailcfg.PortRange{
							First: 22,
							Last:  22,
						},
					}},
					IPProto: []int{int(ipproto.TCP)},
				}},
			},
			waitTest: func(nm *netmap.NetworkMap) bool {
				return len(nm.Peers) > 0
			},
			checks: []check{
				{src: "2.2.2.2", dst: "1.1.1.1", port: 22, want: filter.Accept},
				{src: "2.2.2.2", dst: "1.1.1.1", port: 23, want: filter.Drop}, // different port
				{src: "3.3.3.3", dst: "1.1.1.1", port: 22, want: filter.Drop}, // different src
				{src: "2.2.2.2", dst: "1.1.1.2", port: 22, want: filter.Drop}, // different dst
			},
		},
		{
			name: "capmap_based_peers",
			mapResponse: &tailcfg.MapResponse{
				Node: &tailcfg.Node{
					Addresses: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
				},
				Peers: []*tailcfg.Node{{
					ID:        2,
					Name:      "foo",
					Key:       key,
					Addresses: []netip.Prefix{netip.MustParsePrefix("2.2.2.2/32")},
					CapMap:    tailcfg.NodeCapMap{"X": nil},
				}},
				PacketFilter: []tailcfg.FilterRule{{
					SrcIPs: []string{"cap:X"},
					DstPorts: []tailcfg.NetPortRange{{
						IP: "1.1.1.1/32",
						Ports: tailcfg.PortRange{
							First: 22,
							Last:  22,
						},
					}},
					IPProto: []int{int(ipproto.TCP)},
				}},
			},
			waitTest: func(nm *netmap.NetworkMap) bool {
				return len(nm.Peers) > 0
			},
			checks: []check{
				{src: "2.2.2.2", dst: "1.1.1.1", port: 22, want: filter.Accept},
				{src: "2.2.2.2", dst: "1.1.1.1", port: 23, want: filter.Drop}, // different port
				{src: "3.3.3.3", dst: "1.1.1.1", port: 22, want: filter.Drop}, // different src
				{src: "2.2.2.2", dst: "1.1.1.2", port: 22, want: filter.Drop}, // different dst
			},
		},
		{
			name: "capmap_based_peers_changed",
			mapResponse: &tailcfg.MapResponse{
				Node: &tailcfg.Node{
					Addresses: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
					CapMap:    tailcfg.NodeCapMap{"X-sigil": nil},
				},
				PacketFilter: []tailcfg.FilterRule{{
					SrcIPs: []string{"cap:label-1"},
					DstPorts: []tailcfg.NetPortRange{{
						IP: "1.1.1.1/32",
						Ports: tailcfg.PortRange{
							First: 22,
							Last:  22,
						},
					}},
					IPProto: []int{int(ipproto.TCP)},
				}},
			},
			waitTest: func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.HasCap("X-sigil")
			},
			incrementalMapResponse: &tailcfg.MapResponse{
				PeersChanged: []*tailcfg.Node{{
					ID:        2,
					Name:      "foo",
					Key:       key,
					Addresses: []netip.Prefix{netip.MustParsePrefix("2.2.2.2/32")},
					CapMap:    tailcfg.NodeCapMap{"label-1": nil},
				}},
			},
			incrementalWaitTest: func(nm *netmap.NetworkMap) bool {
				return len(nm.Peers) > 0
			},
			checks: []check{
				{src: "2.2.2.2", dst: "1.1.1.1", port: 22, want: filter.Accept},
				{src: "2.2.2.2", dst: "1.1.1.1", port: 23, want: filter.Drop}, // different port
				{src: "3.3.3.3", dst: "1.1.1.1", port: 22, want: filter.Drop}, // different src
				{src: "2.2.2.2", dst: "1.1.1.2", port: 22, want: filter.Drop}, // different dst
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			controlURL, c := startControl(t)
			s, _, pubKey := startServer(t, ctx, controlURL, "node")

			if test.waitTest(s.lb.NetMap()) {
				t.Fatal("waitTest already passes before sending initial netmap: this will be flaky")
			}

			if !c.AddRawMapResponse(pubKey, test.mapResponse) {
				t.Fatalf("could not send map response to %s", pubKey)
			}

			if err := waitFor(t, ctx, s, test.waitTest); err != nil {
				t.Fatalf("waitFor: %s", err)
			}

			pf := s.lb.GetFilterForTest()

			for _, check := range test.checks {
				got := pf.Check(netip.MustParseAddr(check.src), netip.MustParseAddr(check.dst), check.port, ipproto.TCP)

				want := check.want
				if test.incrementalMapResponse != nil {
					want = filter.Drop
				}
				if got != want {
					t.Errorf("check %s -> %s:%d, got: %s, want: %s", check.src, check.dst, check.port, got, want)
				}
			}

			if test.incrementalMapResponse != nil {
				if test.incrementalWaitTest == nil {
					t.Fatal("incrementalWaitTest must be set if incrementalMapResponse is set")
				}

				if test.incrementalWaitTest(s.lb.NetMap()) {
					t.Fatal("incrementalWaitTest already passes before sending incremental netmap: this will be flaky")
				}

				if !c.AddRawMapResponse(pubKey, test.incrementalMapResponse) {
					t.Fatalf("could not send map response to %s", pubKey)
				}

				if err := waitFor(t, ctx, s, test.incrementalWaitTest); err != nil {
					t.Fatalf("waitFor: %s", err)
				}

				pf := s.lb.GetFilterForTest()

				for _, check := range test.checks {
					got := pf.Check(netip.MustParseAddr(check.src), netip.MustParseAddr(check.dst), check.port, ipproto.TCP)
					if got != check.want {
						t.Errorf("check %s -> %s:%d, got: %s, want: %s", check.src, check.dst, check.port, got, check.want)
					}
				}
			}

		})
	}
}
