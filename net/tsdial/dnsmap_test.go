// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsdial

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

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
		{
			name: "vip_services",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name: "foo.tailnet.",
					Addresses: []netip.Prefix{
						pfx("100.102.103.104/32"),
						pfx("100::123/128"),
					},
					CapMap: tailcfg.NodeCapMap{
						tailcfg.NodeAttrServiceHost: []tailcfg.RawMessage{
							tailcfg.RawMessage(mustMarshal(t, tailcfg.ServiceIPMappings{
								"svc:mydb": {
									netip.MustParseAddr("100.65.32.1"),
									netip.MustParseAddr("fd7a:115c:a1e0::1234"),
								},
							})),
						},
					},
				}).View(),
			},
			want: dnsMap{
				"foo":          ip("100.102.103.104"),
				"foo.tailnet":  ip("100.102.103.104"),
				"mydb.tailnet": ip("100.65.32.1"),
				"mydb":         ip("100.65.32.1"),
			},
		},
		{
			name: "vip_services_v6_only_self",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name: "foo.tailnet.",
					Addresses: []netip.Prefix{
						pfx("100::123/128"),
					},
					CapMap: tailcfg.NodeCapMap{
						tailcfg.NodeAttrServiceHost: []tailcfg.RawMessage{
							tailcfg.RawMessage(mustMarshal(t, tailcfg.ServiceIPMappings{
								"svc:mydb": {
									netip.MustParseAddr("100.65.32.1"),
									netip.MustParseAddr("fd7a:115c:a1e0::1234"),
								},
							})),
						},
					},
				}).View(),
			},
			want: dnsMap{
				"foo":          ip("100::123"),
				"foo.tailnet":  ip("100::123"),
				"mydb.tailnet": ip("fd7a:115c:a1e0::1234"),
				"mydb":         ip("fd7a:115c:a1e0::1234"),
			},
		},
		{
			// VIP service has only IPv4 addrs but self is IPv6-only.
			// Should be excluded entirely since no reachable address exists.
			name: "vip_services_v4_only_addrs_v6_only_self",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name: "foo.tailnet.",
					Addresses: []netip.Prefix{
						pfx("100::123/128"),
					},
					CapMap: tailcfg.NodeCapMap{
						tailcfg.NodeAttrServiceHost: []tailcfg.RawMessage{
							tailcfg.RawMessage(mustMarshal(t, tailcfg.ServiceIPMappings{
								"svc:mydb": {
									netip.MustParseAddr("100.65.32.1"),
									netip.MustParseAddr("100.65.32.2"),
								},
							})),
						},
					},
				}).View(),
			},
			want: dnsMap{
				"foo":         ip("100::123"),
				"foo.tailnet": ip("100::123"),
				// mydb should NOT appear — both addrs are IPv4 and self is v6-only
			},
		},
		{
			// VIP service name collides with a peer name.
			// VIP runs after peers so it overwrites.
			name: "vip_service_overwrites_peer",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name: "foo.tailnet.",
					Addresses: []netip.Prefix{
						pfx("100.102.103.104/32"),
						pfx("100::123/128"),
					},
					CapMap: tailcfg.NodeCapMap{
						tailcfg.NodeAttrServiceHost: []tailcfg.RawMessage{
							tailcfg.RawMessage(mustMarshal(t, tailcfg.ServiceIPMappings{
								"svc:a": {
									netip.MustParseAddr("100.65.32.1"),
								},
							})),
						},
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
				}),
			},
			want: dnsMap{
				"foo":         ip("100.102.103.104"),
				"foo.tailnet": ip("100.102.103.104"),
				"a":           ip("100.65.32.1"), // VIP overwrites peer
				"a.tailnet":   ip("100.65.32.1"), // VIP overwrites peer
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
