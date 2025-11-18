// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsdial

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func nodeViews(v []*tailcfg.Node) []tailcfg.NodeView {
	nv := make([]tailcfg.NodeView, len(v))
	for i, n := range v {
		nv[i] = n.View()
	}
	return nv
}

func TestDNSMapFromNetworkMap(t *testing.T) {
	pfx := netip.MustParsePrefix
	ip := netip.MustParseAddr
	tests := []struct {
		name string
		nm   *netmap.NetworkMap
		want dnsMap
	}{
		{
			name: "self",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name: "foo.tailnet.",
					Addresses: []netip.Prefix{
						pfx("100.102.103.104/32"),
						pfx("100::123/128"),
					},
				}).View(),
			},
			want: dnsMap{
				"foo":         ip("100.102.103.104"),
				"foo.tailnet": ip("100.102.103.104"),
			},
		},
		{
			name: "self_and_peers",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name: "foo.tailnet.",
					Addresses: []netip.Prefix{
						pfx("100.102.103.104/32"),
						pfx("100::123/128"),
					},
				}).View(),
				Peers: []tailcfg.NodeView{
					(&tailcfg.Node{
						Name: "a.tailnet",
						Addresses: []netip.Prefix{
							pfx("100.0.0.201/32"),
							pfx("100::201/128"),
						},
					}).View(),
					(&tailcfg.Node{
						Name: "b.tailnet",
						Addresses: []netip.Prefix{
							pfx("100::202/128"),
						},
					}).View(),
				},
			},
			want: dnsMap{
				"foo":         ip("100.102.103.104"),
				"foo.tailnet": ip("100.102.103.104"),
				"a":           ip("100.0.0.201"),
				"a.tailnet":   ip("100.0.0.201"),
				"b":           ip("100::202"),
				"b.tailnet":   ip("100::202"),
			},
		},
		{
			name: "self_has_v6_only",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name: "foo.tailnet.",
					Addresses: []netip.Prefix{
						pfx("100::123/128"),
					},
				}).View(),
				Peers: nodeViews([]*tailcfg.Node{
					{
						Name: "a.tailnet",
						Addresses: []netip.Prefix{
							pfx("100.0.0.201/32"),
							pfx("100::201/128"),
						},
					},
					{
						Name: "b.tailnet",
						Addresses: []netip.Prefix{
							pfx("100::202/128"),
						},
					},
				}),
			},
			want: dnsMap{
				"foo":         ip("100::123"),
				"foo.tailnet": ip("100::123"),
				"a":           ip("100::201"),
				"a.tailnet":   ip("100::201"),
				"b":           ip("100::202"),
				"b.tailnet":   ip("100::202"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dnsMapFromNetworkMap(tt.nm)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mismatch:\n got %v\nwant %v\n", got, tt.want)
			}
		})
	}
}
