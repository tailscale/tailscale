// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"reflect"
	"testing"

	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/wgcfg"
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

func inRemove(ip netaddr.IP) bool {
	for _, pfx := range removeFromDefaultRoute {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

func TestShrinkDefaultRoute(t *testing.T) {
	tests := []struct {
		route     string
		in        []string
		out       []string
		localIPFn func(netaddr.IP) bool // true if this machine's local IP address should be "in" after shrinking.
	}{
		{
			route: "0.0.0.0/0",
			in:    []string{"1.2.3.4", "25.0.0.1"},
			out: []string{
				"10.0.0.1",
				"10.255.255.255",
				"192.168.0.1",
				"192.168.255.255",
				"172.16.0.1",
				"172.31.255.255",
				"100.101.102.103",
				"224.0.0.1",
				"169.254.169.254",
				// Some random IPv6 stuff that shouldn't be in a v4
				// default route.
				"fe80::",
				"2601::1",
			},
			localIPFn: func(ip netaddr.IP) bool { return !inRemove(ip) && ip.Is4() },
		},
		{
			route: "::/0",
			in:    []string{"::1", "2601::1"},
			out: []string{
				"fe80::1",
				"ff00::1",
				tsaddr.TailscaleULARange().IP.String(),
			},
			localIPFn: func(ip netaddr.IP) bool { return !inRemove(ip) && ip.Is6() },
		},
	}

	for _, test := range tests {
		def := netaddr.MustParseIPPrefix(test.route)
		got, err := shrinkDefaultRoute(def)
		if err != nil {
			t.Fatalf("shrinkDefaultRoute(%q): %v", test.route, err)
		}
		for _, ip := range test.in {
			if !got.Contains(netaddr.MustParseIP(ip)) {
				t.Errorf("shrink(%q).Contains(%v) = false, want true", test.route, ip)
			}
		}
		for _, ip := range test.out {
			if got.Contains(netaddr.MustParseIP(ip)) {
				t.Errorf("shrink(%q).Contains(%v) = true, want false", test.route, ip)
			}
		}
		ips, _, err := interfaces.LocalAddresses()
		if err != nil {
			t.Fatal(err)
		}
		for _, ip := range ips {
			want := test.localIPFn(ip)
			if gotContains := got.Contains(ip); gotContains != want {
				t.Errorf("shrink(%q).Contains(%v) = %v, want %v", test.route, ip, gotContains, want)
			}
		}
	}
}

func TestPeerRoutes(t *testing.T) {
	pp := netaddr.MustParseIPPrefix
	tests := []struct {
		name  string
		peers []wgcfg.Peer
		want  []netaddr.IPPrefix
	}{
		{
			name: "small_v4",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netaddr.IPPrefix{
						pp("100.101.102.103/32"),
					},
				},
			},
			want: []netaddr.IPPrefix{
				pp("100.101.102.103/32"),
			},
		},
		{
			name: "big_v4",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netaddr.IPPrefix{
						pp("100.101.102.103/32"),
						pp("100.101.102.104/32"),
						pp("100.101.102.105/32"),
					},
				},
			},
			want: []netaddr.IPPrefix{
				pp("100.64.0.0/10"),
			},
		},
		{
			name: "has_1_v6",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netaddr.IPPrefix{
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240/128"),
					},
				},
			},
			want: []netaddr.IPPrefix{
				pp("fd7a:115c:a1e0::/48"),
			},
		},
		{
			name: "has_2_v6",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netaddr.IPPrefix{
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240/128"),
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b241/128"),
					},
				},
			},
			want: []netaddr.IPPrefix{
				pp("fd7a:115c:a1e0::/48"),
			},
		},
		{
			name: "big_v4_big_v6",
			peers: []wgcfg.Peer{
				{
					AllowedIPs: []netaddr.IPPrefix{
						pp("100.101.102.103/32"),
						pp("100.101.102.104/32"),
						pp("100.101.102.105/32"),
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b240/128"),
						pp("fd7a:115c:a1e0:ab12:4843:cd96:6258:b241/128"),
					},
				},
			},
			want: []netaddr.IPPrefix{
				pp("fd7a:115c:a1e0::/48"),
				pp("100.64.0.0/10"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerRoutes(tt.peers, 2)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got = %v; want %v", got, tt.want)
			}
		})
	}

}
