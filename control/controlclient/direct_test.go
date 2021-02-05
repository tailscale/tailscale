// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
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

func TestNewDirect(t *testing.T) {
	hi := NewHostinfo()
	ni := tailcfg.NetInfo{LinkType: "wired"}
	hi.NetInfo = &ni

	key, err := wgkey.NewPrivate()
	if err != nil {
		t.Error(err)
	}
	opts := Options{ServerURL: "https://example.com", MachinePrivateKey: key, Hostinfo: hi}
	c, err := NewDirect(opts)
	if err != nil {
		t.Fatal(err)
	}

	if c.serverURL != opts.ServerURL {
		t.Errorf("c.serverURL got %v want %v", c.serverURL, opts.ServerURL)
	}

	if !hi.Equal(c.hostinfo) {
		t.Errorf("c.hostinfo got %v want %v", c.hostinfo, hi)
	}

	changed := c.SetNetInfo(&ni)
	if changed {
		t.Errorf("c.SetNetInfo(ni) want false got %v", changed)
	}
	ni = tailcfg.NetInfo{LinkType: "wifi"}
	changed = c.SetNetInfo(&ni)
	if !changed {
		t.Errorf("c.SetNetInfo(ni) want true got %v", changed)
	}

	changed = c.SetHostinfo(hi)
	if changed {
		t.Errorf("c.SetHostinfo(hi) want false got %v", changed)
	}
	hi = NewHostinfo()
	hi.Hostname = "different host name"
	changed = c.SetHostinfo(hi)
	if !changed {
		t.Errorf("c.SetHostinfo(hi) want true got %v", changed)
	}

	endpoints := []string{"1", "2", "3"}
	changed = c.newEndpoints(12, endpoints)
	if !changed {
		t.Errorf("c.newEndpoints(12) want true got %v", changed)
	}
	changed = c.newEndpoints(12, endpoints)
	if changed {
		t.Errorf("c.newEndpoints(12) want false got %v", changed)
	}
	changed = c.newEndpoints(13, endpoints)
	if !changed {
		t.Errorf("c.newEndpoints(13) want true got %v", changed)
	}
	endpoints = []string{"4", "5", "6"}
	changed = c.newEndpoints(13, endpoints)
	if !changed {
		t.Errorf("c.newEndpoints(13) want true got %v", changed)
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
