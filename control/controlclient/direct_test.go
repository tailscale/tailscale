// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
)

func TestUndeltaPeers(t *testing.T) {
	n := func(id tailcfg.NodeID, name string) *tailcfg.Node {
		return &tailcfg.Node{ID: id, Name: name}
	}
	peers := func(nv ...*tailcfg.Node) []*tailcfg.Node { return nv }
	tests := []struct {
		name   string
		mapRes *tailcfg.MapResponse
		prev   []*tailcfg.Node
		want   []*tailcfg.Node
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
		fmt.Fprintf(&sb, "(%d, %q)", n.ID, n.Name)
	}
	return sb.String()
}
