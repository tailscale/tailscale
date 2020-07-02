// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestNetworkMapConcise(t *testing.T) {
	nodekey := func(b byte) (ret tailcfg.NodeKey) {
		for i := range ret {
			ret[i] = b
		}
		return
	}
	for _, tt := range []struct {
		name string
		nm   *NetworkMap
		want string
	}{
		{
			name: "basic",
			nm: &NetworkMap{
				NodeKey: nodekey(1),
				Peers: []*tailcfg.Node{
					{
						Key:       nodekey(2),
						DERP:      "127.3.3.40:2",
						Endpoints: []string{"192.168.0.100:12", "192.168.0.100:12354"},
					},
					{
						Key:       nodekey(3),
						DERP:      "127.3.3.40:4",
						Endpoints: []string{"10.2.0.100:12", "10.1.0.100:12345"},
					},
				},
			},
			want: "netmap: self: [AQEBA] auth=machine-unknown []\n [AgICA] D2                 :    192.168.0.100:12     192.168.0.100:12354\n [AwMDA] D4                 :       10.2.0.100:12        10.1.0.100:12345\n",
		},
		{
			name: "debug_non_nil",
			nm: &NetworkMap{
				NodeKey: nodekey(1),
				Debug:   &tailcfg.Debug{},
			},
			want: "netmap: self: [AQEBA] auth=machine-unknown debug={} []\n",
		},
		{
			name: "debug_values",
			nm: &NetworkMap{
				NodeKey: nodekey(1),
				Debug:   &tailcfg.Debug{LogHeapPprof: true},
			},
			want: "netmap: self: [AQEBA] auth=machine-unknown debug={\"LogHeapPprof\":true} []\n",
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
