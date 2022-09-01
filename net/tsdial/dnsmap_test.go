// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdial

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

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
				Name: "foo.tailnet",
				Addresses: []netip.Prefix{
					pfx("100.102.103.104/32"),
					pfx("100::123/128"),
				},
			},
			want: dnsMap{
				"foo":         ip("100.102.103.104"),
				"foo.tailnet": ip("100.102.103.104"),
			},
		},
		{
			name: "self_and_peers",
			nm: &netmap.NetworkMap{
				Name: "foo.tailnet",
				Addresses: []netip.Prefix{
					pfx("100.102.103.104/32"),
					pfx("100::123/128"),
				},
				Peers: []*tailcfg.Node{
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
				Name: "foo.tailnet",
				Addresses: []netip.Prefix{
					pfx("100::123/128"),
				},
				Peers: []*tailcfg.Node{
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
				},
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
