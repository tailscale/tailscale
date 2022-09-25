// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/util/must"
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
	withDERP := func(d string) func(*tailcfg.Node) {
		return func(n *tailcfg.Node) {
			n.DERP = d
		}
	}
	withEP := func(ep string) func(*tailcfg.Node) {
		return func(n *tailcfg.Node) {
			n.Endpoints = []string{ep}
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
		{
			name: "ep_change_derp",
			prev: peers(n(1, "foo", withDERP("127.3.3.40:3"))),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:     1,
					DERPRegion: 4,
				}},
			},
			want: peers(n(1, "foo", withDERP("127.3.3.40:4"))),
		},
		{
			name: "ep_change_udp",
			prev: peers(n(1, "foo", withEP("1.2.3.4:111"))),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:    1,
					Endpoints: []string{"1.2.3.4:56"},
				}},
			},
			want: peers(n(1, "foo", withEP("1.2.3.4:56"))),
		},
		{
			name: "ep_change_udp",
			prev: peers(n(1, "foo", withDERP("127.3.3.40:3"), withEP("1.2.3.4:111"))),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:    1,
					Endpoints: []string{"1.2.3.4:56"},
				}},
			},
			want: peers(n(1, "foo", withDERP("127.3.3.40:3"), withEP("1.2.3.4:56"))),
		},
		{
			name: "ep_change_both",
			prev: peers(n(1, "foo", withDERP("127.3.3.40:3"), withEP("1.2.3.4:111"))),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:     1,
					DERPRegion: 2,
					Endpoints:  []string{"1.2.3.4:56"},
				}},
			},
			want: peers(n(1, "foo", withDERP("127.3.3.40:2"), withEP("1.2.3.4:56"))),
		},
		{
			name: "change_key",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID: 1,
					Key:    ptrTo(key.NodePublicFromRaw32(mem.B(append(make([]byte, 31), 'A')))),
				}},
			}, want: peers(&tailcfg.Node{
				ID:   1,
				Name: "foo",
				Key:  key.NodePublicFromRaw32(mem.B(append(make([]byte, 31), 'A'))),
			}),
		},
		{
			name: "change_key_signature",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:       1,
					KeySignature: []byte{3, 4},
				}},
			}, want: peers(&tailcfg.Node{
				ID:           1,
				Name:         "foo",
				KeySignature: []byte{3, 4},
			}),
		},
		{
			name: "change_disco_key",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:   1,
					DiscoKey: ptrTo(key.DiscoPublicFromRaw32(mem.B(append(make([]byte, 31), 'A')))),
				}},
			}, want: peers(&tailcfg.Node{
				ID:       1,
				Name:     "foo",
				DiscoKey: key.DiscoPublicFromRaw32(mem.B(append(make([]byte, 31), 'A'))),
			}),
		},
		{
			name: "change_online",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID: 1,
					Online: ptrTo(true),
				}},
			}, want: peers(&tailcfg.Node{
				ID:     1,
				Name:   "foo",
				Online: ptrTo(true),
			}),
		},
		{
			name: "change_last_seen",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:   1,
					LastSeen: ptrTo(time.Unix(123, 0).UTC()),
				}},
			}, want: peers(&tailcfg.Node{
				ID:       1,
				Name:     "foo",
				LastSeen: ptrTo(time.Unix(123, 0).UTC()),
			}),
		},
		{
			name: "change_key_expiry",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:    1,
					KeyExpiry: ptrTo(time.Unix(123, 0).UTC()),
				}},
			}, want: peers(&tailcfg.Node{
				ID:        1,
				Name:      "foo",
				KeyExpiry: time.Unix(123, 0).UTC(),
			}),
		},
		{
			name: "change_capabilities",
			prev: peers(n(1, "foo")),
			mapRes: &tailcfg.MapResponse{
				PeersChangedPatch: []*tailcfg.PeerChange{{
					NodeID:       1,
					Capabilities: ptrTo([]string{"foo"}),
				}},
			}, want: peers(&tailcfg.Node{
				ID:           1,
				Name:         "foo",
				Capabilities: []string{"foo"},
			}),
		}}

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

func ptrTo[T any](v T) *T {
	return &v
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
	return newMapSession(key.NewNode())
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
			DNSConfig: nil, // implicit
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
	t.Run("implicit_node", func(t *testing.T) {
		someNode := &tailcfg.Node{
			Name: "foo",
		}
		wantNode := &tailcfg.Node{
			Name:                 "foo",
			ComputedName:         "foo",
			ComputedNameWithHost: "foo",
		}
		ms := newTestMapSession(t)

		nm1 := ms.netmapForResponse(&tailcfg.MapResponse{
			Node: someNode,
		})
		if nm1.SelfNode == nil {
			t.Fatal("nil Node in 1st netmap")
		}
		if !reflect.DeepEqual(nm1.SelfNode, wantNode) {
			j, _ := json.Marshal(nm1.SelfNode)
			t.Errorf("Node mismatch in 1st netmap; got: %s", j)
		}

		nm2 := ms.netmapForResponse(&tailcfg.MapResponse{})
		if nm2.SelfNode == nil {
			t.Fatal("nil Node in 1st netmap")
		}
		if !reflect.DeepEqual(nm2.SelfNode, wantNode) {
			j, _ := json.Marshal(nm2.SelfNode)
			t.Errorf("Node mismatch in 2nd netmap; got: %s", j)
		}
	})
}

// TestDeltaDebug tests that tailcfg.Debug values can be omitted in MapResponses
// entirely or have their opt.Bool values unspecified between MapResponses in a
// session and that should mean no change. (as of capver 37). But two Debug
// fields existed prior to capver 37 that weren't opt.Bool; we test that we both
// still accept the non-opt.Bool form from control for RandomizeClientPort and
// ForceBackgroundSTUN and also accept the new form, keeping the old form in
// sync.
func TestDeltaDebug(t *testing.T) {
	type step struct {
		got  *tailcfg.Debug
		want *tailcfg.Debug
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
			name: "sticky-with-old-style-randomize-client-port",
			steps: []step{
				{
					&tailcfg.Debug{RandomizeClientPort: true},
					&tailcfg.Debug{
						RandomizeClientPort:    true,
						SetRandomizeClientPort: "true",
					},
				},
				{
					nil, // not sent by server
					&tailcfg.Debug{
						RandomizeClientPort:    true,
						SetRandomizeClientPort: "true",
					},
				},
			},
		},
		{
			name: "sticky-with-new-style-randomize-client-port",
			steps: []step{
				{
					&tailcfg.Debug{SetRandomizeClientPort: "true"},
					&tailcfg.Debug{
						RandomizeClientPort:    true,
						SetRandomizeClientPort: "true",
					},
				},
				{
					nil, // not sent by server
					&tailcfg.Debug{
						RandomizeClientPort:    true,
						SetRandomizeClientPort: "true",
					},
				},
			},
		},
		{
			name: "opt-bool-sticky-changing-over-time",
			steps: []step{
				{nil, nil},
				{nil, nil},
				{
					&tailcfg.Debug{OneCGNATRoute: "true"},
					&tailcfg.Debug{OneCGNATRoute: "true"},
				},
				{
					nil,
					&tailcfg.Debug{OneCGNATRoute: "true"},
				},
				{
					&tailcfg.Debug{OneCGNATRoute: "false"},
					&tailcfg.Debug{OneCGNATRoute: "false"},
				},
				{
					nil,
					&tailcfg.Debug{OneCGNATRoute: "false"},
				},
			},
		},
		{
			name: "legacy-ForceBackgroundSTUN",
			steps: []step{
				{
					&tailcfg.Debug{ForceBackgroundSTUN: true},
					&tailcfg.Debug{ForceBackgroundSTUN: true, SetForceBackgroundSTUN: "true"},
				},
			},
		},
		{
			name: "opt-bool-SetForceBackgroundSTUN",
			steps: []step{
				{
					&tailcfg.Debug{SetForceBackgroundSTUN: "true"},
					&tailcfg.Debug{ForceBackgroundSTUN: true, SetForceBackgroundSTUN: "true"},
				},
			},
		},
		{
			name: "server-reset-to-default",
			steps: []step{
				{
					&tailcfg.Debug{SetForceBackgroundSTUN: "true"},
					&tailcfg.Debug{ForceBackgroundSTUN: true, SetForceBackgroundSTUN: "true"},
				},
				{
					&tailcfg.Debug{SetForceBackgroundSTUN: "unset"},
					&tailcfg.Debug{ForceBackgroundSTUN: false, SetForceBackgroundSTUN: "unset"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := newTestMapSession(t)
			for stepi, s := range tt.steps {
				nm := ms.netmapForResponse(&tailcfg.MapResponse{Debug: s.got})
				if !reflect.DeepEqual(nm.Debug, s.want) {
					t.Errorf("unexpected result at step index %v; got: %s", stepi, must.Get(json.Marshal(nm.Debug)))
				}
			}
		})
	}
}

// Verifies that copyDebugOptBools doesn't missing any opt.Bools.
func TestCopyDebugOptBools(t *testing.T) {
	rt := reflect.TypeOf(tailcfg.Debug{})
	for i := 0; i < rt.NumField(); i++ {
		sf := rt.Field(i)
		if sf.Type != reflect.TypeOf(opt.Bool("")) {
			continue
		}
		var src, dst tailcfg.Debug
		reflect.ValueOf(&src).Elem().Field(i).Set(reflect.ValueOf(opt.Bool("true")))
		if src == (tailcfg.Debug{}) {
			t.Fatalf("failed to set field %v", sf.Name)
		}
		copyDebugOptBools(&dst, &src)
		if src != dst {
			t.Fatalf("copyDebugOptBools didn't copy field %v", sf.Name)
		}
	}
}
