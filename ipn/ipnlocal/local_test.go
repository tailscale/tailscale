// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"testing"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func TestNetworkMapCompare(t *testing.T) {
	prefix1, err := netaddr.ParseIPPrefix("192.168.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	node1 := &tailcfg.Node{Addresses: []netaddr.IPPrefix{prefix1}}

	prefix2, err := netaddr.ParseIPPrefix("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	node2 := &tailcfg.Node{Addresses: []netaddr.IPPrefix{prefix2}}

	tests := []struct {
		name string
		a, b *netmap.NetworkMap
		want bool
	}{
		{
			"both nil",
			nil,
			nil,
			true,
		},
		{
			"b nil",
			&netmap.NetworkMap{},
			nil,
			false,
		},
		{
			"a nil",
			nil,
			&netmap.NetworkMap{},
			false,
		},
		{
			"both default",
			&netmap.NetworkMap{},
			&netmap.NetworkMap{},
			true,
		},
		{
			"names identical",
			&netmap.NetworkMap{Name: "map1"},
			&netmap.NetworkMap{Name: "map1"},
			true,
		},
		{
			"names differ",
			&netmap.NetworkMap{Name: "map1"},
			&netmap.NetworkMap{Name: "map2"},
			false,
		},
		{
			"Peers identical",
			&netmap.NetworkMap{Peers: []*tailcfg.Node{}},
			&netmap.NetworkMap{Peers: []*tailcfg.Node{}},
			true,
		},
		{
			"Peer list length",
			// length of Peers list differs
			&netmap.NetworkMap{Peers: []*tailcfg.Node{{}}},
			&netmap.NetworkMap{Peers: []*tailcfg.Node{}},
			false,
		},
		{
			"Node names identical",
			&netmap.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "A"}}},
			&netmap.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "A"}}},
			true,
		},
		{
			"Node names differ",
			&netmap.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "A"}}},
			&netmap.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "B"}}},
			false,
		},
		{
			"Node lists identical",
			&netmap.NetworkMap{Peers: []*tailcfg.Node{node1, node1}},
			&netmap.NetworkMap{Peers: []*tailcfg.Node{node1, node1}},
			true,
		},
		{
			"Node lists differ",
			&netmap.NetworkMap{Peers: []*tailcfg.Node{node1, node1}},
			&netmap.NetworkMap{Peers: []*tailcfg.Node{node1, node2}},
			false,
		},
		{
			"Node Users differ",
			// User field is not checked.
			&netmap.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{User: 0}}},
			&netmap.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{User: 1}}},
			true,
		},
	}
	for _, tt := range tests {
		got := dnsMapsEqual(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("%s: Equal = %v; want %v", tt.name, got, tt.want)
		}
	}
}
