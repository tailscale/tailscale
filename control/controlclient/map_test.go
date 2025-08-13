// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go4.org/mem"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/ptr"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/util/mak"
	"tailscale.com/util/must"
)

func eps(s ...string) []netip.AddrPort {
	var eps []netip.AddrPort
	for _, ep := range s {
		eps = append(eps, netip.MustParseAddrPort(ep))
	}
	return eps
}

func TestUpdatePeersStateFromResponse(t *testing.T) {
	var curTime time.Time

	online := func(v bool) func(*tailcfg.Node) {
		return func(n *tailcfg.Node) {
			n.Online = &v
		}
	}
	seenAt := func(t time.Time) func(*tailcfg.Node) {
		return func(n *tailcfg.Node) {
			n.LastSeen = &t
		}
	}
	withDERP := func(regionID int) func(*tailcfg.Node) {
		return func(n *tailcfg.Node) {
			n.HomeDERP = regionID
		}
	}
	withEP := func(ep string) func(*tailcfg.Node) {
		return func(n *tailcfg.Node) {
			n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort(ep)}
		}
	}
	n := func(id tailcfg.NodeID, name string, mod ...func(*tailcfg.Node)) *tailcfg.Node {
		n := &tailcfg.Node{ID: id, Name: name}
		for _, f := range mod {
			f(n)
		}
		return n
	}
	peers := func(nv ...*tailcfg.Node) []*tailcfg.Node { return nv }
	tests := []struct {
		name      string
		mapRes    *tailcfg.MapResponse
		curTime   time.Time
		prev      []*tailcfg.Node
		want      []*tailcfg.Node
		wantStats updateStats
	}{
		{
			name: "full_peers",
			mapRes: &tailcfg.MapResponse{
				Peers: peers(n(1, "foo"), n(2, "bar")),
			},
			want: peers(n(1, "foo"), n(2, "bar")),
			wantStats: updateStats{
				allNew: true,
				added:  2,
			},
		},
		{
			name: "full_peers_ignores_deltas",
			mapRes: &tailcfg.MapResponse{
				Peers:        peers(n(1, "foo"), n(2, "bar")),
				PeersRemoved: []tailcfg.NodeID{2},
			},
			want: peers(n(1, "foo"), n(2, "bar")),
			wantStats: updateStats{
				allNew: true,
				added:  2,
			},
		},
		{
			name: "add_and_update",
			prev: peers(n(1, "foo"), n(2, "bar")),
			mapRes: &tailcfg.MapResponse{
				PeersChanged: peers(n(0, "zero"), n(2, "bar2"), n(3, "three")),
			},
			want: peers(n(0, "zero"), n(1, "foo"), n(2, "bar2"), n(3, "three")),
			wantStats: updateStats{
				added:   2, // added IDs 0 and 3
				changed: 1, // changed ID 2
			},
		},
		{
			name: "remove",
			prev: peers(n(1, "foo"), n(2, "bar")),
			mapRes: &tailcfg.MapResponse{
				PeersRemoved: []tailcfg.NodeID{1, 3, 4},
			},
			want: peers(n(2, "bar")),
			wantStats: updateStats{
				removed: 1, // ID 1
			},
		},
		{
			name: "add_and_remove",
			prev: peers(n(1, "foo"), n(2, "bar")),
			mapRes: &tailcfg.MapResponse{
				PeersChanged: peers(n(1, "foo2")),
				PeersRemoved: []tailcfg.NodeID{2},
			},
			want: peers(n(1, "foo2")),
			wantStats: updateStats{
				changed: 1,
				removed: 1,
			},
		},
		{
			name:   "unchanged",
			prev:   peers(n(1, "foo"), n(2, "bar")),
			mapRes: &tailcfg.MapResponse{},
			want:   peers(n(1, "foo"), n(2, "bar")),
		},
		{
			name: "online_change",
			prev: peers(n(1, "foo"), n(2, "bar")),
			mapRes: &tailcfg.MapResponse{
				OnlineChange: map[tailcfg.NodeID]bool{
					1:   true,
					404: true,
				},
			},
			want: peers(
				n(1, "foo", online(true)),
				n(2, "bar"),
			),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "online_change_offline",
			prev: peers(n(1, "foo"), n(2, "bar")),
			mapRes: &tailcfg.MapResponse{
				OnlineChange: map[tailcfg.NodeID]bool{
					1: false,
					2: true,
				},
			},
			want: peers(
				n(1, "foo", online(false)),
				n(2, "bar", online(true)),
			),
			wantStats: updateStats{changed: 2},
		},
		{
			name:    "peer_seen_at",
			prev:    peers(n(1, "foo", seenAt(time.Unix(111, 0))), n(2, "bar")),
			curTime: time.Unix(123, 0),
			mapRes: &tailcfg.MapResponse{
				PeerSeenChange: map[tailcfg.NodeID]bool{
					1: false,
					2: true,
				},
			},
			want: peers(
				n(1, "foo"),
				n(2, "bar", seenAt(time.Unix(123, 0))),
			),
			wantStats: updateStats{changed: 2},
		},
		{
			name: "ep_change_derp",
			prev: peers(n(1, "foo", withDERP(3))),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:     1,
					DERPRegion: 4,
				}},
			},
			want:      peers(n(1, "foo", withDERP(4))),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "ep_change_udp",
			prev: peers(n(1, "foo", withEP("1.2.3.4:111"))),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:    1,
					Endpoints: eps("1.2.3.4:56"),
				}},
			},
			want:      peers(n(1, "foo", withEP("1.2.3.4:56"))),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "ep_change_udp_2",
			prev: peers(n(1, "foo", withDERP(3), withEP("1.2.3.4:111"))),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:    1,
					Endpoints: eps("1.2.3.4:56"),
				}},
			},
			want:      peers(n(1, "foo", withDERP(3), withEP("1.2.3.4:56"))),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "ep_change_both",
			prev: peers(n(1, "foo", withDERP(3), withEP("1.2.3.4:111"))),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:     1,
					DERPRegion: 2,
					Endpoints:  eps("1.2.3.4:56"),
				}},
			},
			want:      peers(n(1, "foo", withDERP(2), withEP("1.2.3.4:56"))),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "change_key",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID: 1,
					Key:    ptr.To(key.NodePublicFromRaw32(mem.B(append(make([]byte, 31), 'A')))),
				}},
			}, want: peers(&tailcfg.Node{
				ID:   1,
				Name: "foo",
				Key:  key.NodePublicFromRaw32(mem.B(append(make([]byte, 31), 'A'))),
			}),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "change_key_signature",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:       1,
					KeySignature: []byte{3, 4},
				}},
			},
			want: peers(&tailcfg.Node{
				ID:           1,
				Name:         "foo",
				KeySignature: []byte{3, 4},
			}),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "change_disco_key",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:   1,
					DiscoKey: ptr.To(key.DiscoPublicFromRaw32(mem.B(append(make([]byte, 31), 'A')))),
				}},
			},
			want: peers(&tailcfg.Node{
				ID:       1,
				Name:     "foo",
				DiscoKey: key.DiscoPublicFromRaw32(mem.B(append(make([]byte, 31), 'A'))),
			}),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "change_online",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID: 1,
					Online: ptr.To(true),
				}},
			},
			want: peers(&tailcfg.Node{
				ID:     1,
				Name:   "foo",
				Online: ptr.To(true),
			}),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "change_last_seen",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:   1,
					LastSeen: ptr.To(time.Unix(123, 0).UTC()),
				}},
			},
			want: peers(&tailcfg.Node{
				ID:       1,
				Name:     "foo",
				LastSeen: ptr.To(time.Unix(123, 0).UTC()),
			}),
			wantStats: updateStats{changed: 1},
		},
		{
			name: "change_key_expiry",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:    1,
					KeyExpiry: ptr.To(time.Unix(123, 0).UTC()),
				}},
			},
			want: peers(&tailcfg.Node{
				ID:        1,
				Name:      "foo",
				KeyExpiry: time.Unix(123, 0).UTC(),
			}),
			wantStats: updateStats{changed: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.curTime.IsZero() {
				curTime = tt.curTime
				tstest.Replace(t, &clock, tstime.Clock(tstest.NewClock(tstest.ClockOpts{Start: curTime})))
			}
			ms := newTestMapSession(t, nil)
			for _, n := range tt.prev {
				mak.Set(&ms.peers, n.ID, n.View())
			}

			gotStats := ms.updatePeersStateFromResponse(tt.mapRes)
			if gotStats != tt.wantStats {
				t.Errorf("got stats = %+v; want %+v", gotStats, tt.wantStats)
			}

			var got []*tailcfg.Node
			for _, vp := range ms.sortedPeers() {
				got = append(got, vp.AsStruct())
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("wrong results\n got: %s\nwant: %s", formatNodes(got), formatNodes(tt.want))
			}
		})
	}
}

func formatNodes(nodes []*tailcfg.Node) string {
	var sb strings.Builder
	for i, n := range nodes {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "(%d, %q", n.ID, n.Name)

		if n.Online != nil {
			fmt.Fprintf(&sb, ", online=%v", *n.Online)
		}
		if n.LastSeen != nil {
			fmt.Fprintf(&sb, ", lastSeen=%v", n.LastSeen.Unix())
		}
		if n.Key != (key.NodePublic{}) {
			fmt.Fprintf(&sb, ", key=%v", n.Key.String())
		}
		if n.Expired {
			fmt.Fprintf(&sb, ", expired=true")
		}
		sb.WriteString(")")
	}
	return sb.String()
}

func newTestMapSession(t testing.TB, nu NetmapUpdater) *mapSession {
	ms := newMapSession(key.NewNode(), nu, new(controlknobs.Knobs))
	t.Cleanup(ms.Close)
	ms.logf = t.Logf
	return ms
}

func (ms *mapSession) netmapForResponse(res *tailcfg.MapResponse) *netmap.NetworkMap {
	ms.updateStateFromResponse(res)
	return ms.netmap()
}

func TestNetmapForResponse(t *testing.T) {
	t.Run("implicit_packetfilter", func(t *testing.T) {
		somePacketFilter := []tailcfg.FilterRule{
			{
				SrcIPs: []string{"*"},
				DstPorts: []tailcfg.NetPortRange{
					{IP: "10.2.3.4", Ports: tailcfg.PortRange{First: 22, Last: 22}},
				},
			},
		}
		ms := newTestMapSession(t, nil)
		nm1 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:         new(tailcfg.Node),
			PacketFilter: somePacketFilter,
		})
		if len(nm1.PacketFilter) == 0 {
			t.Fatalf("zero length PacketFilter")
		}
		nm2 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:         new(tailcfg.Node),
			PacketFilter: nil, // testing that the server can omit this.
		})
		if len(nm1.PacketFilter) == 0 {
			t.Fatalf("zero length PacketFilter in 2nd netmap")
		}
		if !reflect.DeepEqual(nm1.PacketFilter, nm2.PacketFilter) {
			t.Error("packet filters differ")
		}
	})
	t.Run("implicit_dnsconfig", func(t *testing.T) {
		someDNSConfig := &tailcfg.DNSConfig{Domains: []string{"foo", "bar"}}
		ms := newTestMapSession(t, nil)
		nm1 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:      new(tailcfg.Node),
			DNSConfig: someDNSConfig,
		})
		if !reflect.DeepEqual(nm1.DNS, *someDNSConfig) {
			t.Fatalf("1st DNS wrong")
		}
		nm2 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:      new(tailcfg.Node),
			DNSConfig: nil, // implicit
		})
		if !reflect.DeepEqual(nm2.DNS, *someDNSConfig) {
			t.Fatalf("2nd DNS wrong")
		}
	})
	t.Run("collect_services", func(t *testing.T) {
		ms := newTestMapSession(t, nil)
		var nm *netmap.NetworkMap
		wantCollect := func(v bool) {
			t.Helper()
			if nm.CollectServices != v {
				t.Errorf("netmap.CollectServices = %v; want %v", nm.CollectServices, v)
			}
		}

		nm = ms.netmapForResponse(&tailcfg.MapResponse{
			Node: new(tailcfg.Node),
		})
		wantCollect(false)

		nm = ms.netmapForResponse(&tailcfg.MapResponse{
			Node:            new(tailcfg.Node),
			CollectServices: "false",
		})
		wantCollect(false)

		nm = ms.netmapForResponse(&tailcfg.MapResponse{
			Node:            new(tailcfg.Node),
			CollectServices: "true",
		})
		wantCollect(true)

		nm = ms.netmapForResponse(&tailcfg.MapResponse{
			Node:            new(tailcfg.Node),
			CollectServices: "",
		})
		wantCollect(true)
	})
	t.Run("implicit_domain", func(t *testing.T) {
		ms := newTestMapSession(t, nil)
		var nm *netmap.NetworkMap
		want := func(v string) {
			t.Helper()
			if nm.Domain != v {
				t.Errorf("netmap.Domain = %q; want %q", nm.Domain, v)
			}
		}
		nm = ms.netmapForResponse(&tailcfg.MapResponse{
			Node:   new(tailcfg.Node),
			Domain: "foo.com",
		})
		want("foo.com")

		nm = ms.netmapForResponse(&tailcfg.MapResponse{
			Node: new(tailcfg.Node),
		})
		want("foo.com")
	})
	t.Run("implicit_node", func(t *testing.T) {
		someNode := &tailcfg.Node{
			Name: "foo",
		}
		wantNode := (&tailcfg.Node{
			Name:                 "foo",
			ComputedName:         "foo",
			ComputedNameWithHost: "foo",
		}).View()
		ms := newTestMapSession(t, nil)
		mapRes := &tailcfg.MapResponse{
			Node: someNode,
		}
		initDisplayNames(mapRes.Node.View(), mapRes)
		ms.updateStateFromResponse(mapRes)
		nm1 := ms.netmap()
		if !nm1.SelfNode.Valid() {
			t.Fatal("nil Node in 1st netmap")
		}
		if !reflect.DeepEqual(nm1.SelfNode, wantNode) {
			j, _ := json.Marshal(nm1.SelfNode)
			t.Errorf("Node mismatch in 1st netmap; got: %s", j)
		}

		ms.updateStateFromResponse(&tailcfg.MapResponse{})
		nm2 := ms.netmap()
		if !nm2.SelfNode.Valid() {
			t.Fatal("nil Node in 1st netmap")
		}
		if !reflect.DeepEqual(nm2.SelfNode, wantNode) {
			j, _ := json.Marshal(nm2.SelfNode)
			t.Errorf("Node mismatch in 2nd netmap; got: %s", j)
		}
	})
	t.Run("named_packetfilter", func(t *testing.T) {
		pfA := []tailcfg.FilterRule{
			{
				SrcIPs: []string{"10.0.0.1"},
				DstPorts: []tailcfg.NetPortRange{
					{IP: "10.2.3.4", Ports: tailcfg.PortRange{First: 22, Last: 22}},
				},
			},
		}
		pfB := []tailcfg.FilterRule{
			{
				SrcIPs: []string{"10.0.0.2"},
				DstPorts: []tailcfg.NetPortRange{
					{IP: "10.2.3.4", Ports: tailcfg.PortRange{First: 22, Last: 22}},
				},
			},
		}
		ms := newTestMapSession(t, nil)

		// Mix of old & new style (PacketFilter and PacketFilters).
		nm1 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:         new(tailcfg.Node),
			PacketFilter: pfA,
			PacketFilters: map[string][]tailcfg.FilterRule{
				"pf-b": pfB,
			},
		})
		if got, want := len(nm1.PacketFilter), 2; got != want {
			t.Fatalf("PacketFilter length = %v; want %v", got, want)
		}
		if got, want := first(nm1.PacketFilter[0].Srcs).String(), "10.0.0.1/32"; got != want {
			t.Fatalf("PacketFilter[0].Srcs = %v; want %v", got, want)
		}
		if got, want := first(nm1.PacketFilter[1].Srcs).String(), "10.0.0.2/32"; got != want {
			t.Fatalf("PacketFilter[0].Srcs = %v; want %v", got, want)
		}

		// No-op change. Remember the old stuff.
		nm2 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:          new(tailcfg.Node),
			PacketFilter:  nil,
			PacketFilters: nil,
		})
		if got, want := len(nm2.PacketFilter), 2; got != want {
			t.Fatalf("PacketFilter length = %v; want %v", got, want)
		}
		if !reflect.DeepEqual(nm1.PacketFilter, nm2.PacketFilter) {
			t.Error("packet filters differ")
		}

		// New style only, with clear.
		nm3 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:         new(tailcfg.Node),
			PacketFilter: nil,
			PacketFilters: map[string][]tailcfg.FilterRule{
				"*":    nil,
				"pf-b": pfB,
			},
		})
		if got, want := len(nm3.PacketFilter), 1; got != want {
			t.Fatalf("PacketFilter length = %v; want %v", got, want)
		}
		if got, want := first(nm3.PacketFilter[0].Srcs).String(), "10.0.0.2/32"; got != want {
			t.Fatalf("PacketFilter[0].Srcs = %v; want %v", got, want)
		}

		// New style only, adding pfA back, not as the legacy "base" layer:.
		nm4 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:         new(tailcfg.Node),
			PacketFilter: nil,
			PacketFilters: map[string][]tailcfg.FilterRule{
				"pf-a": pfA,
			},
		})
		if got, want := len(nm4.PacketFilter), 2; got != want {
			t.Fatalf("PacketFilter length = %v; want %v", got, want)
		}
		if got, want := first(nm4.PacketFilter[0].Srcs).String(), "10.0.0.1/32"; got != want {
			t.Fatalf("PacketFilter[0].Srcs = %v; want %v", got, want)
		}
		if got, want := first(nm4.PacketFilter[1].Srcs).String(), "10.0.0.2/32"; got != want {
			t.Fatalf("PacketFilter[0].Srcs = %v; want %v", got, want)
		}
	})
}

func first[T any](s []T) T {
	if len(s) == 0 {
		var zero T
		return zero
	}
	return s[0]
}

func TestDeltaDERPMap(t *testing.T) {
	regions1 := map[int]*tailcfg.DERPRegion{
		1: {
			RegionID: 1,
			Nodes: []*tailcfg.DERPNode{{
				Name:     "derp1a",
				RegionID: 1,
				HostName: "derp1a" + tailcfg.DotInvalid,
				IPv4:     "169.254.169.254",
				IPv6:     "none",
			}},
		},
	}

	// As above, but with a changed IPv4 addr
	regions2 := map[int]*tailcfg.DERPRegion{1: regions1[1].Clone()}
	regions2[1].Nodes[0].IPv4 = "127.0.0.1"

	type step struct {
		got  *tailcfg.DERPMap
		want *tailcfg.DERPMap
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{
			name: "nothing-to-nothing",
			steps: []step{
				{nil, nil},
				{nil, nil},
			},
		},
		{
			name: "regions-sticky",
			steps: []step{
				{&tailcfg.DERPMap{Regions: regions1}, &tailcfg.DERPMap{Regions: regions1}},
				{&tailcfg.DERPMap{}, &tailcfg.DERPMap{Regions: regions1}},
			},
		},
		{
			name: "regions-change",
			steps: []step{
				{&tailcfg.DERPMap{Regions: regions1}, &tailcfg.DERPMap{Regions: regions1}},
				{&tailcfg.DERPMap{Regions: regions2}, &tailcfg.DERPMap{Regions: regions2}},
			},
		},
		{
			name: "home-params",
			steps: []step{
				// Send a DERP map
				{&tailcfg.DERPMap{Regions: regions1}, &tailcfg.DERPMap{Regions: regions1}},
				// Send home params, want to still have the same regions
				{
					&tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{
						RegionScore: map[int]float64{1: 0.5},
					}},
					&tailcfg.DERPMap{Regions: regions1, HomeParams: &tailcfg.DERPHomeParams{
						RegionScore: map[int]float64{1: 0.5},
					}},
				},
			},
		},
		{
			name: "home-params-sub-fields",
			steps: []step{
				// Send a DERP map with home params
				{
					&tailcfg.DERPMap{Regions: regions1, HomeParams: &tailcfg.DERPHomeParams{
						RegionScore: map[int]float64{1: 0.5},
					}},
					&tailcfg.DERPMap{Regions: regions1, HomeParams: &tailcfg.DERPHomeParams{
						RegionScore: map[int]float64{1: 0.5},
					}},
				},
				// Sending a struct with a 'HomeParams' field but nil RegionScore doesn't change home params...
				{
					&tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{RegionScore: nil}},
					&tailcfg.DERPMap{Regions: regions1, HomeParams: &tailcfg.DERPHomeParams{
						RegionScore: map[int]float64{1: 0.5},
					}},
				},
				// ... but sending one with a non-nil and empty RegionScore field zeroes that out.
				{
					&tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{RegionScore: map[int]float64{}}},
					&tailcfg.DERPMap{Regions: regions1, HomeParams: &tailcfg.DERPHomeParams{
						RegionScore: map[int]float64{},
					}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := newTestMapSession(t, nil)
			for stepi, s := range tt.steps {
				nm := ms.netmapForResponse(&tailcfg.MapResponse{DERPMap: s.got})
				if !reflect.DeepEqual(nm.DERPMap, s.want) {
					t.Errorf("unexpected result at step index %v; got: %s", stepi, logger.AsJSON(nm.DERPMap))
				}
			}
		})
	}
}

func TestPeerChangeDiff(t *testing.T) {
	tests := []struct {
		name      string
		a, b      *tailcfg.Node
		want      *tailcfg.PeerChange // nil means want ok=false, unless wantEqual is set
		wantEqual bool                // means test wants (nil, true)
	}{
		{
			name:      "eq",
			a:         &tailcfg.Node{ID: 1},
			b:         &tailcfg.Node{ID: 1},
			wantEqual: true,
		},
		{
			name: "patch-derp",
			a:    &tailcfg.Node{ID: 1, HomeDERP: 1},
			b:    &tailcfg.Node{ID: 1, HomeDERP: 2},
			want: &tailcfg.PeerChange{NodeID: 1, DERPRegion: 2},
		},
		{
			name: "patch-endpoints",
			a:    &tailcfg.Node{ID: 1, Endpoints: eps("10.0.0.1:1")},
			b:    &tailcfg.Node{ID: 1, Endpoints: eps("10.0.0.2:2")},
			want: &tailcfg.PeerChange{NodeID: 1, Endpoints: eps("10.0.0.2:2")},
		},
		{
			name: "patch-cap",
			a:    &tailcfg.Node{ID: 1, Cap: 1},
			b:    &tailcfg.Node{ID: 1, Cap: 2},
			want: &tailcfg.PeerChange{NodeID: 1, Cap: 2},
		},
		{
			name: "patch-lastseen",
			a:    &tailcfg.Node{ID: 1, LastSeen: ptr.To(time.Unix(1, 0))},
			b:    &tailcfg.Node{ID: 1, LastSeen: ptr.To(time.Unix(2, 0))},
			want: &tailcfg.PeerChange{NodeID: 1, LastSeen: ptr.To(time.Unix(2, 0))},
		},
		{
			name: "patch-online-to-true",
			a:    &tailcfg.Node{ID: 1, Online: ptr.To(false)},
			b:    &tailcfg.Node{ID: 1, Online: ptr.To(true)},
			want: &tailcfg.PeerChange{NodeID: 1, Online: ptr.To(true)},
		},
		{
			name: "patch-online-to-false",
			a:    &tailcfg.Node{ID: 1, Online: ptr.To(true)},
			b:    &tailcfg.Node{ID: 1, Online: ptr.To(false)},
			want: &tailcfg.PeerChange{NodeID: 1, Online: ptr.To(false)},
		},
		{
			name: "mix-patchable-and-not",
			a:    &tailcfg.Node{ID: 1, Cap: 1},
			b:    &tailcfg.Node{ID: 1, Cap: 2, StableID: "foo"},
			want: nil,
		},
		{
			name: "miss-change-stableid",
			a:    &tailcfg.Node{ID: 1},
			b:    &tailcfg.Node{ID: 1, StableID: "diff"},
			want: nil,
		},
		{
			name: "miss-change-id",
			a:    &tailcfg.Node{ID: 1},
			b:    &tailcfg.Node{ID: 2},
			want: nil,
		},
		{
			name: "miss-change-name",
			a:    &tailcfg.Node{ID: 1, Name: "foo"},
			b:    &tailcfg.Node{ID: 1, Name: "bar"},
			want: nil,
		},
		{
			name: "miss-change-user",
			a:    &tailcfg.Node{ID: 1, User: 1},
			b:    &tailcfg.Node{ID: 1, User: 2},
			want: nil,
		},
		{
			name: "miss-change-masq-v4",
			a:    &tailcfg.Node{ID: 1, SelfNodeV4MasqAddrForThisPeer: ptr.To(netip.MustParseAddr("100.64.0.1"))},
			b:    &tailcfg.Node{ID: 1, SelfNodeV4MasqAddrForThisPeer: ptr.To(netip.MustParseAddr("100.64.0.2"))},
			want: nil,
		},
		{
			name: "miss-change-masq-v6",
			a:    &tailcfg.Node{ID: 1, SelfNodeV6MasqAddrForThisPeer: ptr.To(netip.MustParseAddr("2001::3456"))},
			b:    &tailcfg.Node{ID: 1, SelfNodeV6MasqAddrForThisPeer: ptr.To(netip.MustParseAddr("2001::3006"))},
			want: nil,
		},
		{
			name: "patch-capmap-add-value-to-existing-key",
			a:    &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil}},
			b:    &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: []tailcfg.RawMessage{"true"}}},
			want: &tailcfg.PeerChange{NodeID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: []tailcfg.RawMessage{"true"}}},
		},
		{
			name: "patch-capmap-add-new-key",
			a:    &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil}},
			b:    &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil, tailcfg.CapabilityDebug: nil}},
			want: &tailcfg.PeerChange{NodeID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil, tailcfg.CapabilityDebug: nil}},
		}, {
			name: "patch-capmap-remove-key",
			a:    &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil}},
			b:    &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{}},
			want: &tailcfg.PeerChange{NodeID: 1, CapMap: tailcfg.NodeCapMap{}},
		}, {
			name: "patch-capmap-remove-as-nil",
			a:    &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil}},
			b:    &tailcfg.Node{ID: 1},
			want: &tailcfg.PeerChange{NodeID: 1, CapMap: tailcfg.NodeCapMap{}},
		}, {
			name: "patch-capmap-add-key-to-empty-map",
			a:    &tailcfg.Node{ID: 1},
			b:    &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil}},
			want: &tailcfg.PeerChange{NodeID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil}},
		},
		{
			name:      "patch-capmap-no-change",
			a:         &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil}},
			b:         &tailcfg.Node{ID: 1, CapMap: tailcfg.NodeCapMap{tailcfg.CapabilityAdmin: nil}},
			wantEqual: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc, ok := peerChangeDiff(tt.a.View(), tt.b)
			if tt.wantEqual {
				if !ok || pc != nil {
					t.Errorf("got (%p, %v); want (nil, true); pc=%v", pc, ok, logger.AsJSON(pc))
				}
				return
			}
			if (pc != nil) != ok {
				t.Fatalf("inconsistent ok=%v, pc=%p", ok, pc)
			}
			if !reflect.DeepEqual(pc, tt.want) {
				t.Errorf("mismatch\n got: %v\nwant: %v\n", logger.AsJSON(pc), logger.AsJSON(tt.want))
			}
		})
	}
}

func TestPeerChangeDiffAllocs(t *testing.T) {
	a := &tailcfg.Node{ID: 1}
	b := &tailcfg.Node{ID: 1}
	n := testing.AllocsPerRun(10000, func() {
		diff, ok := peerChangeDiff(a.View(), b)
		if !ok || diff != nil {
			t.Fatalf("unexpected result: (%s, %v)", logger.AsJSON(diff), ok)
		}
	})
	if n != 0 {
		t.Errorf("allocs = %v; want 0", int(n))
	}
}

type countingNetmapUpdater struct {
	full atomic.Int64
}

func (nu *countingNetmapUpdater) UpdateFullNetmap(nm *netmap.NetworkMap) {
	nu.full.Add(1)
}

// tests (*mapSession).patchifyPeersChanged; smaller tests are in TestPeerChangeDiff
func TestPatchifyPeersChanged(t *testing.T) {
	hi := (&tailcfg.Hostinfo{}).View()
	tests := []struct {
		name string
		mr0  *tailcfg.MapResponse // initial
		mr1  *tailcfg.MapResponse // incremental
		want *tailcfg.MapResponse // what the incremental one should've been mutated to
	}{
		{
			name: "change_one_endpoint",
			mr0: &tailcfg.MapResponse{
				Node: &tailcfg.Node{Name: "foo.bar.ts.net."},
				Peers: []*tailcfg.Node{
					{ID: 1, Hostinfo: hi},
				},
			},
			mr1: &tailcfg.MapResponse{
				PeersChanged: []*tailcfg.Node{
					{ID: 1, Endpoints: eps("10.0.0.1:1111"), Hostinfo: hi},
				},
			},
			want: &tailcfg.MapResponse{
				PeersChanged: nil,
				PeersChangedPatch: []*tailcfg.PeerChange{
					{NodeID: 1, Endpoints: eps("10.0.0.1:1111")},
				},
			},
		},
		{
			name: "change_some",
			mr0: &tailcfg.MapResponse{
				Node: &tailcfg.Node{Name: "foo.bar.ts.net."},
				Peers: []*tailcfg.Node{
					{ID: 1, HomeDERP: 1, Hostinfo: hi},
					{ID: 2, HomeDERP: 2, Hostinfo: hi},
					{ID: 3, HomeDERP: 3, Hostinfo: hi},
				},
			},
			mr1: &tailcfg.MapResponse{
				PeersChanged: []*tailcfg.Node{
					{ID: 1, HomeDERP: 11, Hostinfo: hi},
					{ID: 2, StableID: "other-change", Hostinfo: hi},
					{ID: 3, HomeDERP: 33, Hostinfo: hi},
					{ID: 4, HomeDERP: 4, Hostinfo: hi},
				},
			},
			want: &tailcfg.MapResponse{
				PeersChanged: []*tailcfg.Node{
					{ID: 2, StableID: "other-change", Hostinfo: hi},
					{ID: 4, HomeDERP: 4, Hostinfo: hi},
				},
				PeersChangedPatch: []*tailcfg.PeerChange{
					{NodeID: 1, DERPRegion: 11},
					{NodeID: 3, DERPRegion: 33},
				},
			},
		},
		{
			name: "change_exitnodednsresolvers",
			mr0: &tailcfg.MapResponse{
				Node: &tailcfg.Node{Name: "foo.bar.ts.net."},
				Peers: []*tailcfg.Node{
					{ID: 1, ExitNodeDNSResolvers: []*dnstype.Resolver{{Addr: "dns.exmaple.com"}}, Hostinfo: hi},
				},
			},
			mr1: &tailcfg.MapResponse{
				PeersChanged: []*tailcfg.Node{
					{ID: 1, ExitNodeDNSResolvers: []*dnstype.Resolver{{Addr: "dns2.exmaple.com"}}, Hostinfo: hi},
				},
			},
			want: &tailcfg.MapResponse{
				PeersChanged: []*tailcfg.Node{
					{ID: 1, ExitNodeDNSResolvers: []*dnstype.Resolver{{Addr: "dns2.exmaple.com"}}, Hostinfo: hi},
				},
			},
		},
		{
			name: "same_exitnoderesolvers",
			mr0: &tailcfg.MapResponse{
				Node: &tailcfg.Node{Name: "foo.bar.ts.net."},
				Peers: []*tailcfg.Node{
					{ID: 1, ExitNodeDNSResolvers: []*dnstype.Resolver{{Addr: "dns.exmaple.com"}}, Hostinfo: hi},
				},
			},
			mr1: &tailcfg.MapResponse{
				PeersChanged: []*tailcfg.Node{
					{ID: 1, ExitNodeDNSResolvers: []*dnstype.Resolver{{Addr: "dns.exmaple.com"}}, Hostinfo: hi},
				},
			},
			want: &tailcfg.MapResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nu := &countingNetmapUpdater{}
			ms := newTestMapSession(t, nu)
			ms.updateStateFromResponse(tt.mr0)
			mr1 := new(tailcfg.MapResponse)
			must.Do(json.Unmarshal(must.Get(json.Marshal(tt.mr1)), mr1))
			ms.patchifyPeersChanged(mr1)
			opts := []cmp.Option{
				cmp.Comparer(func(a, b netip.AddrPort) bool { return a == b }),
			}
			if diff := cmp.Diff(tt.want, mr1, opts...); diff != "" {
				t.Errorf("wrong result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUpgradeNode(t *testing.T) {
	a1 := netip.MustParsePrefix("0.0.0.1/32")
	a2 := netip.MustParsePrefix("0.0.0.2/32")
	a3 := netip.MustParsePrefix("0.0.0.3/32")
	a4 := netip.MustParsePrefix("0.0.0.4/32")

	tests := []struct {
		name string
		in   *tailcfg.Node
		want *tailcfg.Node
		also func(t *testing.T, got *tailcfg.Node) // optional
	}{
		{
			name: "nil",
			in:   nil,
			want: nil,
		},
		{
			name: "empty",
			in:   new(tailcfg.Node),
			want: new(tailcfg.Node),
		},
		{
			name: "derp-both",
			in:   &tailcfg.Node{HomeDERP: 1, LegacyDERPString: tailcfg.DerpMagicIP + ":2"},
			want: &tailcfg.Node{HomeDERP: 1},
		},
		{
			name: "derp-str-only",
			in:   &tailcfg.Node{LegacyDERPString: tailcfg.DerpMagicIP + ":2"},
			want: &tailcfg.Node{HomeDERP: 2},
		},
		{
			name: "derp-int-only",
			in:   &tailcfg.Node{HomeDERP: 2},
			want: &tailcfg.Node{HomeDERP: 2},
		},
		{
			name: "implicit-allowed-ips-all-set",
			in:   &tailcfg.Node{Addresses: []netip.Prefix{a1, a2}, AllowedIPs: []netip.Prefix{a3, a4}},
			want: &tailcfg.Node{Addresses: []netip.Prefix{a1, a2}, AllowedIPs: []netip.Prefix{a3, a4}},
		},
		{
			name: "implicit-allowed-ips-only-address-set",
			in:   &tailcfg.Node{Addresses: []netip.Prefix{a1, a2}},
			want: &tailcfg.Node{Addresses: []netip.Prefix{a1, a2}, AllowedIPs: []netip.Prefix{a1, a2}},
			also: func(t *testing.T, got *tailcfg.Node) {
				if t.Failed() {
					return
				}
				if &got.Addresses[0] == &got.AllowedIPs[0] {
					t.Error("Addresses and AllowIPs alias the same memory")
				}
			},
		},
		{
			name: "implicit-allowed-ips-set-empty-slice",
			in:   &tailcfg.Node{Addresses: []netip.Prefix{a1, a2}, AllowedIPs: []netip.Prefix{}},
			want: &tailcfg.Node{Addresses: []netip.Prefix{a1, a2}, AllowedIPs: []netip.Prefix{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got *tailcfg.Node
			if tt.in != nil {
				got = ptr.To(*tt.in) // shallow clone
			}
			upgradeNode(got)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("wrong result (-want +got):\n%s", diff)
			}
			if tt.also != nil {
				tt.also(t, got)
			}
		})
	}

}

func BenchmarkMapSessionDelta(b *testing.B) {
	for _, size := range []int{10, 100, 1_000, 10_000} {
		b.Run(fmt.Sprintf("size_%d", size), func(b *testing.B) {
			ctx := context.Background()
			nu := &countingNetmapUpdater{}
			ms := newTestMapSession(b, nu)
			res := &tailcfg.MapResponse{
				Node: &tailcfg.Node{
					ID:   1,
					Name: "foo.bar.ts.net.",
				},
			}
			for i := range size {
				res.Peers = append(res.Peers, &tailcfg.Node{
					ID:         tailcfg.NodeID(i + 2),
					Name:       fmt.Sprintf("peer%d.bar.ts.net.", i),
					HomeDERP:   10,
					Addresses:  []netip.Prefix{netip.MustParsePrefix("100.100.2.3/32"), netip.MustParsePrefix("fd7a:115c:a1e0::123/128")},
					AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.100.2.3/32"), netip.MustParsePrefix("fd7a:115c:a1e0::123/128")},
					Endpoints:  eps("192.168.1.2:345", "192.168.1.3:678"),
					Hostinfo: (&tailcfg.Hostinfo{
						OS:       "fooOS",
						Hostname: "MyHostname",
						Services: []tailcfg.Service{
							{Proto: "peerapi4", Port: 1234},
							{Proto: "peerapi6", Port: 1234},
							{Proto: "peerapi-dns-proxy", Port: 1},
						},
					}).View(),
					LastSeen: ptr.To(time.Unix(int64(i), 0)),
				})
			}
			ms.HandleNonKeepAliveMapResponse(ctx, res)

			b.ResetTimer()
			b.ReportAllocs()

			// Now for the core of the benchmark loop, just toggle
			// a single node's online status.
			for i := range b.N {
				if err := ms.HandleNonKeepAliveMapResponse(ctx, &tailcfg.MapResponse{
					OnlineChange: map[tailcfg.NodeID]bool{
						2: i%2 == 0,
					},
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestNetmapDisplayMessage checks that the various diff operations
// (add/update/delete/clear) for [tailcfg.DisplayMessage] in a
// [tailcfg.MapResponse] work as expected.
func TestNetmapDisplayMessage(t *testing.T) {
	type test struct {
		name         string
		initialState *tailcfg.MapResponse
		mapResponse  tailcfg.MapResponse
		wantMessages map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage
	}

	tests := []test{
		{
			name: "basic-set",
			mapResponse: tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"test-message": {
						Title:               "Testing",
						Text:                "This is a test message",
						Severity:            tailcfg.SeverityHigh,
						ImpactsConnectivity: true,
						PrimaryAction: &tailcfg.DisplayMessageAction{
							URL:   "https://www.example.com",
							Label: "Learn more",
						},
					},
				},
			},
			wantMessages: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"test-message": {
					Title:               "Testing",
					Text:                "This is a test message",
					Severity:            tailcfg.SeverityHigh,
					ImpactsConnectivity: true,
					PrimaryAction: &tailcfg.DisplayMessageAction{
						URL:   "https://www.example.com",
						Label: "Learn more",
					},
				},
			},
		},
		{
			name: "delete-one",
			initialState: &tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"message-a": {
						Title: "Message A",
					},
					"message-b": {
						Title: "Message B",
					},
				},
			},
			mapResponse: tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"message-a": nil,
				},
			},
			wantMessages: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"message-b": {
					Title: "Message B",
				},
			},
		},
		{
			name: "update-one",
			initialState: &tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"message-a": {
						Title: "Message A",
					},
					"message-b": {
						Title: "Message B",
					},
				},
			},
			mapResponse: tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"message-a": {
						Title: "Message A updated",
					},
				},
			},
			wantMessages: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"message-a": {
					Title: "Message A updated",
				},
				"message-b": {
					Title: "Message B",
				},
			},
		},
		{
			name: "add-one",
			initialState: &tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"message-a": {
						Title: "Message A",
					},
				},
			},
			mapResponse: tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"message-b": {
						Title: "Message B",
					},
				},
			},
			wantMessages: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"message-a": {
					Title: "Message A",
				},
				"message-b": {
					Title: "Message B",
				},
			},
		},
		{
			name: "delete-all",
			initialState: &tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"message-a": {
						Title: "Message A",
					},
					"message-b": {
						Title: "Message B",
					},
				},
			},
			mapResponse: tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"*": nil,
				},
			},
			wantMessages: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{},
		},
		{
			name: "delete-all-and-add",
			initialState: &tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"message-a": {
						Title: "Message A",
					},
					"message-b": {
						Title: "Message B",
					},
				},
			},
			mapResponse: tailcfg.MapResponse{
				DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
					"*": nil,
					"message-c": {
						Title: "Message C",
					},
				},
			},
			wantMessages: map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage{
				"message-c": {
					Title: "Message C",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ms := newTestMapSession(t, nil)

			if test.initialState != nil {
				ms.netmapForResponse(test.initialState)
			}

			nm := ms.netmapForResponse(&test.mapResponse)

			if diff := cmp.Diff(test.wantMessages, nm.DisplayMessages, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unexpected warnings (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNetmapHealthIntegration checks that we get the expected health warnings
// from processing a [tailcfg.MapResponse] containing health messages and passing the
// [netmap.NetworkMap] to a [health.Tracker].
func TestNetmapHealthIntegration(t *testing.T) {
	ms := newTestMapSession(t, nil)
	ht := health.NewTracker(eventbustest.NewBus(t))

	ht.SetIPNState("NeedsLogin", true)
	ht.GotStreamedMapResponse()

	nm := ms.netmapForResponse(&tailcfg.MapResponse{
		Health: []string{
			"Test message",
			"Another message",
		},
	})
	ht.SetControlHealth(nm.DisplayMessages)

	want := map[health.WarnableCode]health.UnhealthyState{
		"control-health.health-c0719e9a8d5d838d861dc6f675c899d2b309a3a65bb9fe6b11e5afcbf9a2c0b1": {
			WarnableCode: "control-health.health-c0719e9a8d5d838d861dc6f675c899d2b309a3a65bb9fe6b11e5afcbf9a2c0b1",
			Title:        "Coordination server reports an issue",
			Severity:     health.SeverityMedium,
			Text:         "The coordination server is reporting a health issue: Test message",
		},
		"control-health.health-1dc7017a73a3c55c0d6a8423e3813c7ab6562d9d3064c2ec6ac7822f61b1db9c": {
			WarnableCode: "control-health.health-1dc7017a73a3c55c0d6a8423e3813c7ab6562d9d3064c2ec6ac7822f61b1db9c",
			Title:        "Coordination server reports an issue",
			Severity:     health.SeverityMedium,
			Text:         "The coordination server is reporting a health issue: Another message",
		},
	}

	got := maps.Clone(ht.CurrentState().Warnings)
	for k := range got {
		if !strings.HasPrefix(string(k), "control-health") {
			delete(got, k)
		}
	}

	if d := cmp.Diff(want, got, cmpopts.IgnoreFields(health.UnhealthyState{}, "ETag")); d != "" {
		t.Fatalf("CurrentStatus().Warnings[\"control-health*\"] different than expected (-want +got)\n%s", d)
	}
}

// TestNetmapDisplayMessageIntegration checks that we get the expected health
// warnings from processing a [tailcfg.MapResponse] that contains DisplayMessages and
// passing the [netmap.NetworkMap] to a [health.Tracker].
func TestNetmapDisplayMessageIntegration(t *testing.T) {
	ms := newTestMapSession(t, nil)
	ht := health.NewTracker(eventbustest.NewBus(t))

	ht.SetIPNState("NeedsLogin", true)
	ht.GotStreamedMapResponse()
	baseWarnings := ht.CurrentState().Warnings

	nm := ms.netmapForResponse(&tailcfg.MapResponse{
		DisplayMessages: map[tailcfg.DisplayMessageID]*tailcfg.DisplayMessage{
			"test-message": {
				Title:               "Testing",
				Text:                "This is a test message",
				Severity:            tailcfg.SeverityHigh,
				ImpactsConnectivity: true,
				PrimaryAction: &tailcfg.DisplayMessageAction{
					URL:   "https://www.example.com",
					Label: "Learn more",
				},
			},
		},
	})
	ht.SetControlHealth(nm.DisplayMessages)

	state := ht.CurrentState()

	// Ignore warnings that aren't from the netmap
	for k := range baseWarnings {
		delete(state.Warnings, k)
	}

	want := map[health.WarnableCode]health.UnhealthyState{
		"control-health.test-message": {
			WarnableCode:        "control-health.test-message",
			Title:               "Testing",
			Text:                "This is a test message",
			Severity:            health.SeverityHigh,
			ImpactsConnectivity: true,
			PrimaryAction: &health.UnhealthyStateAction{
				URL:   "https://www.example.com",
				Label: "Learn more",
			},
		},
	}

	if diff := cmp.Diff(want, state.Warnings, cmpopts.IgnoreFields(health.UnhealthyState{}, "ETag")); diff != "" {
		t.Errorf("unexpected message contents (-want +got):\n%s", diff)
	}
}

func TestNetmapForMapResponseForDebug(t *testing.T) {
	mr := &tailcfg.MapResponse{
		Node: &tailcfg.Node{
			ID:   1,
			Name: "foo.bar.ts.net.",
		},
		Peers: []*tailcfg.Node{
			{ID: 2, Name: "peer1.bar.ts.net.", HomeDERP: 1},
			{ID: 3, Name: "peer2.bar.ts.net.", HomeDERP: 1},
		},
	}
	ms := newTestMapSession(t, nil)
	nm1 := ms.netmapForResponse(mr)

	prefs := &ipn.Prefs{Persist: &persist.Persist{PrivateNodeKey: ms.privateNodeKey}}
	nm2, err := NetmapFromMapResponseForDebug(t.Context(), prefs.View().Persist(), mr)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nm1, nm2) {
		t.Errorf("mismatch\nnm1: %s\nnm2: %s\n", logger.AsJSON(nm1), logger.AsJSON(nm2))
	}
}
