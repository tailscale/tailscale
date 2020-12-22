// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/tailcfg"
)

func testNodeKey(b byte) (ret tailcfg.NodeKey) {
	for i := range ret {
		ret[i] = b
	}
	return
}

func testDiscoKey(hexPrefix string) (ret tailcfg.DiscoKey) {
	b, err := hex.DecodeString(hexPrefix)
	if err != nil {
		panic(err)
	}
	copy(ret[:], b)
	return
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
				Peers: []*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
					{
						Key:       testNodeKey(3),
						DERP:      "127.3.3.40:4",
						Endpoints: []string{"10.2.0.100:12", "10.1.0.100:12345"},
					},
				},
			},
			want: "netmap: self: [AQEBA] auth=machine-unknown u=? []\n [AgICA] D2                 :    192.168.0.100:12     192.168.0.100:12354\n [AwMDA] D4                 :       10.2.0.100:12        10.1.0.100:12345\n",
		},
		{
			name: "debug_non_nil",
			nm: &NetworkMap{
				NodeKey: testNodeKey(1),
				Debug:   &tailcfg.Debug{},
			},
			want: "netmap: self: [AQEBA] auth=machine-unknown u=? debug={} []\n",
		},
		{
			name: "debug_values",
			nm: &NetworkMap{
				NodeKey: testNodeKey(1),
				Debug:   &tailcfg.Debug{LogHeapPprof: true},
			},
			want: "netmap: self: [AQEBA] auth=machine-unknown u=? debug={\"LogHeapPprof\":true} []\n",
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
				Peers: []*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
				},
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
				},
			},
			want: "",
		},
		{
			name: "header_change",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
				},
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(2),
				Peers: []*tailcfg.Node{
					{
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
				},
			},
			want: "-netmap: self: [AQEBA] auth=machine-unknown u=? []\n+netmap: self: [AgICA] auth=machine-unknown u=? []\n",
		},
		{
			name: "peer_add",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						ID:        2,
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
				},
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						ID:        1,
						Key:       testNodeKey(1),
						DERP:      "127.3.3.40:1",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
					{
						ID:        2,
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
					{
						ID:        3,
						Key:       testNodeKey(3),
						DERP:      "127.3.3.40:3",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
				},
			},
			want: "+ [AQEBA] D1                 :    192.168.0.100:12     192.168.0.100:12354\n+ [AwMDA] D3                 :    192.168.0.100:12     192.168.0.100:12354\n",
		},
		{
			name: "peer_remove",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						ID:        1,
						Key:       testNodeKey(1),
						DERP:      "127.3.3.40:1",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
					{
						ID:        2,
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
					{
						ID:        3,
						Key:       testNodeKey(3),
						DERP:      "127.3.3.40:3",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
				},
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						ID:        2,
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
				},
			},
			want: "- [AQEBA] D1                 :    192.168.0.100:12     192.168.0.100:12354\n- [AwMDA] D3                 :    192.168.0.100:12     192.168.0.100:12354\n",
		},
		{
			name: "peer_port_change",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						ID:        2,
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "1.1.1.1:1"},
					},
				},
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						ID:        2,
						Key:       testNodeKey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "1.1.1.1:2"},
					},
				},
			},
			want: "- [AgICA] D2                 :    192.168.0.100:12             1.1.1.1:1  \n+ [AgICA] D2                 :    192.168.0.100:12             1.1.1.1:2  \n",
		},
		{
			name: "disco_key_only_change",
			a: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						ID:         2,
						Key:        testNodeKey(2),
						DERP:       "127.3.3.40:2",
						Endpoints:  []string{"192.168.0.100:41641", "1.1.1.1:41641"},
						DiscoKey:   testDiscoKey("f00f00f00f"),
						AllowedIPs: []wgcfg.CIDR{{IP: wgcfg.IPv4(100, 102, 103, 104), Mask: 32}},
					},
				},
			},
			b: &NetworkMap{
				NodeKey: testNodeKey(1),
				Peers: []*tailcfg.Node{
					{
						ID:         2,
						Key:        testNodeKey(2),
						DERP:       "127.3.3.40:2",
						Endpoints:  []string{"192.168.0.100:41641", "1.1.1.1:41641"},
						DiscoKey:   testDiscoKey("ba4ba4ba4b"),
						AllowedIPs: []wgcfg.CIDR{{IP: wgcfg.IPv4(100, 102, 103, 104), Mask: 32}},
					},
				},
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

func TestNewHostinfo(t *testing.T) {
	hi := NewHostinfo()
	if hi == nil {
		t.Fatal("no Hostinfo")
	}
	j, err := json.MarshalIndent(hi, "  ", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %s", j)
}
