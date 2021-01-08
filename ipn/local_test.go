// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/tailcfg"
	"testing"
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
		a, b *controlclient.NetworkMap
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
			&controlclient.NetworkMap{},
			nil,
			false,
		},
		{
			"a nil",
			nil,
			&controlclient.NetworkMap{},
			false,
		},
		{
			"both default",
			&controlclient.NetworkMap{},
			&controlclient.NetworkMap{},
			true,
		},
		{
			"names identical",
			&controlclient.NetworkMap{Name: "map1"},
			&controlclient.NetworkMap{Name: "map1"},
			true,
		},
		{
			"names differ",
			&controlclient.NetworkMap{Name: "map1"},
			&controlclient.NetworkMap{Name: "map2"},
			false,
		},
		{
			"Peers identical",
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{}},
			true,
		},
		{
			"Peer list length",
			// length of Peers list differs
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{{}}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{}},
			false,
		},
		{
			"Node names identical",
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "A"}}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "A"}}},
			true,
		},
		{
			"Node names differ",
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "A"}}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "B"}}},
			false,
		},
		{
			"Node lists identical",
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{node1, node1}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{node1, node1}},
			true,
		},
		{
			"Node lists differ",
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{node1, node1}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{node1, node2}},
			false,
		},
		{
			"Node Users differ",
			// User field is not checked.
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{User: 0}}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{User: 1}}},
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
