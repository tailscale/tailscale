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
		a, b *controlclient.NetworkMap
		want bool
	}{
		{
			nil,
			nil,
			true,
		},
		{
			&controlclient.NetworkMap{},
			nil,
			false,
		},
		{
			nil,
			&controlclient.NetworkMap{},
			false,
		},
		{
			&controlclient.NetworkMap{},
			&controlclient.NetworkMap{},
			true,
		},
		{
			&controlclient.NetworkMap{Name: "map1"},
			&controlclient.NetworkMap{Name: "map1"},
			true,
		},
		{
			&controlclient.NetworkMap{Name: "map1"},
			&controlclient.NetworkMap{Name: "map2"},
			false,
		},
		{
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{}},
			true,
		},
		{
			// length of Peers list differs
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{{}}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{}},
			false,
		},
		{
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "A"}}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "A"}}},
			true,
		},
		{
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "A"}}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{Name: "B"}}},
			false,
		},
		{
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{node1, node1}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{node1, node1}},
			true,
		},
		{
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{node1, node1}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{node1, node2}},
			false,
		},
		{
			// User field is not checked.
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{User: 0}}},
			&controlclient.NetworkMap{Peers: []*tailcfg.Node{&tailcfg.Node{User: 1}}},
			true,
		},
	}
	for i, tt := range tests {
		got := dnsMapsEqual(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("%d. Equal = %v; want %v", i, got, tt.want)
		}
	}
}
