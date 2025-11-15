// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmap

import (
	"encoding/hex"
	"net/netip"
	"reflect"
	"testing"

	"go4.org/mem"
	"tailscale.com/net/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/typewalk"
	"tailscale.com/types/key"
)

func testNodeKey(b byte) (ret key.NodePublic) {
	var bs [key.NodePublicRawLen]byte
	for i := range bs {
		bs[i] = b
	}
	return key.NodePublicFromRaw32(mem.B(bs[:]))
}

func testDiscoKey(hexPrefix string) (ret key.DiscoPublic) {
	b, err := hex.DecodeString(hexPrefix)
	if err != nil {
		panic(err)
	}
	// this function is used with short hexes, so zero-extend the raw
	// value.
	var bs [32]byte
	copy(bs[:], b)
	return key.DiscoPublicFromRaw32(mem.B(bs[:]))
}

func nodeViews(v []*tailcfg.Node) []tailcfg.NodeView {
	nv := make([]tailcfg.NodeView, len(v))
	for i, n := range v {
		nv[i] = n.View()
	}
	return nv
}

func eps(s ...string) []netip.AddrPort {
	var eps []netip.AddrPort
	for _, ep := range s {
		eps = append(eps, netip.MustParseAddrPort(ep))
	}
	return eps
}

func TestNetworkMapConcise(t *testing.T) {
	for _, tt := range []struct {
		name string
		nm   *NetworkMap
		want string
	}{
		{
			name: "basic",
			nm: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
					{
						Key:       testNodeKey(3),
						HomeDERP:  4,
						Endpoints: eps("10.2.0.100:12", "10.1.0.100:12345"),
					},
				}),
			},
			want: "netmap: self: [AQEBA] auth=machine-unknown u=? []\n [AgICA] D2                 :    192.168.0.100:12     192.168.0.100:12354\n [AwMDA] D4                 :       10.2.0.100:12        10.1.0.100:12345\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			n := int(testing.AllocsPerRun(1000, func() {
				got = tt.nm.Concise()
			}))
			t.Logf("Allocs = %d", n)
			if got != tt.want {
				t.Errorf("Wrong output\n Got: %q\nWant: %q\n## Got (unescaped):\n%s\n## Want (unescaped):\n%s\n", got, tt.want, got, tt.want)
			}
		})
	}
}

func TestConciseDiffFrom(t *testing.T) {
	for _, tt := range []struct {
		name string
		a, b *NetworkMap
		want string
	}{
		{
			name: "no_change",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
				}),
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
				}),
			},
			want: "",
		},
		{
			name: "header_change",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
				}),
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(2),
				Peers: nodeViews([]*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
				}),
			},
			want: "-netmap: self: [AQEBA] auth=machine-unknown u=? []\n+netmap: self: [AgICA] auth=machine-unknown u=? []\n",
		},
		{
			name: "peer_add",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						ID:        2,
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
				}),
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						ID:        1,
						Key:       testNodeKey(1),
						HomeDERP:  1,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
					{
						ID:        2,
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
					{
						ID:        3,
						Key:       testNodeKey(3),
						HomeDERP:  3,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
				}),
			},
			want: "+ [AQEBA] D1                 :    192.168.0.100:12     192.168.0.100:12354\n+ [AwMDA] D3                 :    192.168.0.100:12     192.168.0.100:12354\n",
		},
		{
			name: "peer_remove",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						ID:        1,
						Key:       testNodeKey(1),
						HomeDERP:  1,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
					{
						ID:        2,
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
					{
						ID:        3,
						Key:       testNodeKey(3),
						HomeDERP:  3,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
				}),
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						ID:        2,
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "192.168.0.100:12354"),
					},
				}),
			},
			want: "- [AQEBA] D1                 :    192.168.0.100:12     192.168.0.100:12354\n- [AwMDA] D3                 :    192.168.0.100:12     192.168.0.100:12354\n",
		},
		{
			name: "peer_port_change",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						ID:        2,
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "1.1.1.1:1"),
					},
				}),
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						ID:        2,
						Key:       testNodeKey(2),
						HomeDERP:  2,
						Endpoints: eps("192.168.0.100:12", "1.1.1.1:2"),
					},
				}),
			},
			want: "- [AgICA] D2                 :    192.168.0.100:12             1.1.1.1:1  \n+ [AgICA] D2                 :    192.168.0.100:12             1.1.1.1:2  \n",
		},
		{
			name: "disco_key_only_change",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						ID:         2,
						Key:        testNodeKey(2),
						HomeDERP:   2,
						Endpoints:  eps("192.168.0.100:41641", "1.1.1.1:41641"),
						DiscoKey:   testDiscoKey("f00f00f00f"),
						AllowedIPs: []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(100, 102, 103, 104), 32)},
					},
				}),
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: nodeViews([]*tailcfg.Node{
					{
						ID:         2,
						Key:        testNodeKey(2),
						HomeDERP:   2,
						Endpoints:  eps("192.168.0.100:41641", "1.1.1.1:41641"),
						DiscoKey:   testDiscoKey("ba4ba4ba4b"),
						AllowedIPs: []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(100, 102, 103, 104), 32)},
					},
				}),
			},
			want: "- [AgICA] d:f00f00f00f000000 D2 100.102.103.104 :   192.168.0.100:41641         1.1.1.1:41641\n+ [AgICA] d:ba4ba4ba4b000000 D2 100.102.103.104 :   192.168.0.100:41641         1.1.1.1:41641\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			n := int(testing.AllocsPerRun(50, func() {
				got = tt.b.ConciseDiffFrom(tt.a)
			}))
			t.Logf("Allocs = %d", n)
			if got != tt.want {
				t.Errorf("Wrong output\n Got: %q\nWant: %q\n## Got (unescaped):\n%s\n## Want (unescaped):\n%s\n", got, tt.want, got, tt.want)
			}
		})
	}
}

func TestPeerIndexByNodeID(t *testing.T) {
	var nilPtr *NetworkMap
	if nilPtr.PeerIndexByNodeID(123) != -1 {
		t.Errorf("nil PeerIndexByNodeID should return -1")
	}
	var nm NetworkMap
	const min = 2
	const max = 10000
	const hole = max / 2
	for nid := tailcfg.NodeID(2); nid <= max; nid++ {
		if nid == hole {
			continue
		}
		nm.Peers = append(nm.Peers, (&tailcfg.Node{ID: nid}).View())
	}
	for want, nv := range nm.Peers {
		got := nm.PeerIndexByNodeID(nv.ID())
		if got != want {
			t.Errorf("PeerIndexByNodeID(%v) = %v; want %v", nv.ID(), got, want)
		}
	}
	for _, miss := range []tailcfg.NodeID{min - 1, hole, max + 1} {
		if got := nm.PeerIndexByNodeID(miss); got != -1 {
			t.Errorf("PeerIndexByNodeID(%v) = %v; want -1", miss, got)
		}
	}
}

func TestNoPrivateKeyMaterial(t *testing.T) {
	private := key.PrivateTypesForTest()
	for path := range typewalk.MatchingPaths(reflect.TypeFor[NetworkMap](), private.Contains) {
		t.Errorf("NetworkMap contains private key material at path: %q", path.Name)
	}
}
