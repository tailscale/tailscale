// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/wgkey"
)

func TestUndeltaPeers(t *testing.T) {
	defer func(old func() time.Time) { clockNow = old }(clockNow)

	var curTime time.Time
	clockNow = func() time.Time {
		return curTime
	}
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
	n := func(id tailcfg.NodeID, name string, mod ...func(*tailcfg.Node)) *tailcfg.Node {
		n := &tailcfg.Node{ID: id, Name: name}
		for _, f := range mod {
			f(n)
		}
		return n
	}
	peers := func(nv ...*tailcfg.Node) []*tailcfg.Node { return nv }
	tests := []struct {
		name    string
		mapRes  *tailcfg.MapResponse
		curTime time.Time
		prev    []*tailcfg.Node
		want    []*tailcfg.Node
	}{
		{
			name: "full_peers",
			mapRes: &tailcfg.MapResponse{
				Peers: peers(n(1, "foo"), n(2, "bar")),
			},
			want: peers(n(1, "foo"), n(2, "bar")),
		},
		{
			name: "full_peers_ignores_deltas",
			mapRes: &tailcfg.MapResponse{
				Peers:        peers(n(1, "foo"), n(2, "bar")),
				PeersRemoved: []tailcfg.NodeID{2},
			},
			want: peers(n(1, "foo"), n(2, "bar")),
		},
		{
			name: "add_and_update",
			prev: peers(n(1, "foo"), n(2, "bar")),
			mapRes: &tailcfg.MapResponse{
				PeersChanged: peers(n(0, "zero"), n(2, "bar2"), n(3, "three")),
			},
			want: peers(n(0, "zero"), n(1, "foo"), n(2, "bar2"), n(3, "three")),
		},
		{
			name: "remove",
			prev: peers(n(1, "foo"), n(2, "bar")),
			mapRes: &tailcfg.MapResponse{
				PeersRemoved: []tailcfg.NodeID{1},
			},
			want: peers(n(2, "bar")),
		},
		{
			name: "add_and_remove",
			prev: peers(n(1, "foo"), n(2, "bar")),
			mapRes: &tailcfg.MapResponse{
				PeersChanged: peers(n(1, "foo2")),
				PeersRemoved: []tailcfg.NodeID{2},
			},
			want: peers(n(1, "foo2")),
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
					1: true,
				},
			},
			want: peers(
				n(1, "foo", online(true)),
				n(2, "bar"),
			),
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
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.curTime.IsZero() {
				curTime = tt.curTime
			}
			undeltaPeers(tt.mapRes, tt.prev)
			if !reflect.DeepEqual(tt.mapRes.Peers, tt.want) {
				t.Errorf("wrong results\n got: %s\nwant: %s", formatNodes(tt.mapRes.Peers), formatNodes(tt.want))
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
		var extra string
		if n.Online != nil {
			extra += fmt.Sprintf(", online=%v", *n.Online)
		}
		if n.LastSeen != nil {
			extra += fmt.Sprintf(", lastSeen=%v", n.LastSeen.Unix())
		}
		fmt.Fprintf(&sb, "(%d, %q%s)", n.ID, n.Name, extra)
	}
	return sb.String()
}

func newTestMapSession(t *testing.T) *mapSession {
	k, err := wgkey.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return newMapSession(k)
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
		ms := newTestMapSession(t)
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
		ms := newTestMapSession(t)
		nm1 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:      new(tailcfg.Node),
			DNSConfig: someDNSConfig,
		})
		if !reflect.DeepEqual(nm1.DNS, *someDNSConfig) {
			t.Fatalf("1st DNS wrong")
		}
		nm2 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node:      new(tailcfg.Node),
			DNSConfig: nil, // implict
		})
		if !reflect.DeepEqual(nm2.DNS, *someDNSConfig) {
			t.Fatalf("2nd DNS wrong")
		}
	})
	t.Run("collect_services", func(t *testing.T) {
		ms := newTestMapSession(t)
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
		ms := newTestMapSession(t)
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
}
