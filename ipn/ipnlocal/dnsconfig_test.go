// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	"tailscale.com/appc"
	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/util/cloudenv"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
	"tailscale.com/wgengine/wgcfg"
)

func ipps(ippStrs ...string) (ipps []netip.Prefix) {
	for _, s := range ippStrs {
		if ip, err := netip.ParseAddr(s); err == nil {
			ipps = append(ipps, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		ipps = append(ipps, netip.MustParsePrefix(s))
	}
	return
}

func ips(ss ...string) (ips []netip.Addr) {
	for _, s := range ss {
		ips = append(ips, netip.MustParseAddr(s))
	}
	return
}

func nodeViews(v []*tailcfg.Node) []tailcfg.NodeView {
	nv := make([]tailcfg.NodeView, len(v))
	for i, n := range v {
		nv[i] = n.View()
	}
	return nv
}

func TestDNSConfigForNetmap(t *testing.T) {
	tests := []struct {
		name    string
		nm      *netmap.NetworkMap
		expired bool
		peers   []tailcfg.NodeView
		os      string // version.OS value; empty means linux
		cloud   cloudenv.Cloud
		prefs   *ipn.Prefs
		want    *dns.Config
		wantLog string
	}{
		{
			name:  "empty",
			nm:    &netmap.NetworkMap{},
			prefs: &ipn.Prefs{},
			want: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts:  map[dnsname.FQDN][]netip.Addr{},
			},
		},
		{
			name: "self_name_and_peers",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name:      "myname.net.",
					Addresses: ipps("100.101.101.101"),
				}).View(),
			},
			peers: nodeViews([]*tailcfg.Node{
				{
					ID:        1,
					Name:      "peera.net",
					Addresses: ipps("100.102.0.1", "100.102.0.2", "fe75::1001", "fe75::1002"),
				},
				{
					ID:        2,
					Name:      "b.net",
					Addresses: ipps("100.102.0.1", "100.102.0.2", "fe75::2"),
				},
				{
					ID:        3,
					Name:      "v6-only.net",
					Addresses: ipps("fe75::3"), // no IPv4, so we don't ignore IPv6
				},
			}),
			prefs: &ipn.Prefs{},
			want: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"b.net.":       ips("100.102.0.1", "100.102.0.2"),
					"myname.net.":  ips("100.101.101.101"),
					"peera.net.":   ips("100.102.0.1", "100.102.0.2"),
					"v6-only.net.": ips("fe75::3"),
				},
			},
		},
		{
			name: "subdomain_resolve_capability",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name:      "myname.net.",
					Addresses: ipps("100.101.101.101"),
				}).View(),
				AllCaps: set.SetOf([]tailcfg.NodeCapability{tailcfg.NodeAttrDNSSubdomainResolve}),
			},
			peers: nodeViews([]*tailcfg.Node{
				{
					ID:        1,
					Name:      "peer-with-cap.net.",
					Addresses: ipps("100.102.0.1"),
					CapMap:    tailcfg.NodeCapMap{tailcfg.NodeAttrDNSSubdomainResolve: nil},
				},
				{
					ID:        2,
					Name:      "peer-without-cap.net.",
					Addresses: ipps("100.102.0.2"),
				},
			}),
			prefs: &ipn.Prefs{},
			want: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"myname.net.":           ips("100.101.101.101"),
					"peer-with-cap.net.":    ips("100.102.0.1"),
					"peer-without-cap.net.": ips("100.102.0.2"),
				},
				SubdomainHosts: set.Of[dnsname.FQDN]("myname.net.", "peer-with-cap.net."),
			},
		},
		{
			// An ephemeral node with only an IPv6 address
			// should get IPv6 records for all its peers,
			// even if they have IPv4.
			name: "v6_only_self",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name:      "myname.net.",
					Addresses: ipps("fe75::1"),
				}).View(),
			},
			peers: nodeViews([]*tailcfg.Node{
				{
					ID:        1,
					Name:      "peera.net.",
					Addresses: ipps("100.102.0.1", "100.102.0.2", "fe75::1001"),
				},
				{
					ID:        2,
					Name:      "b.net",
					Addresses: ipps("100.102.0.1", "100.102.0.2", "fe75::2"),
				},
				{
					ID:        3,
					Name:      "v6-only.net",
					Addresses: ipps("fe75::3"), // no IPv4, so we don't ignore IPv6
				},
			}),
			prefs: &ipn.Prefs{},
			want: &dns.Config{
				OnlyIPv6: true,
				Routes:   map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"b.net.":       ips("fe75::2"),
					"myname.net.":  ips("fe75::1"),
					"peera.net.":   ips("fe75::1001"),
					"v6-only.net.": ips("fe75::3"),
				},
			},
		},
		{
			name: "extra_records",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name:      "myname.net.",
					Addresses: ipps("100.101.101.101"),
				}).View(),
				DNS: tailcfg.DNSConfig{
					ExtraRecords: []tailcfg.DNSRecord{
						{Name: "foo.com", Value: "1.2.3.4"},
						{Name: "bar.com", Value: "1::6"},
						{Name: "sdlfkjsdklfj", Type: "IGNORE"},
					},
				},
			},
			prefs: &ipn.Prefs{},
			want: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"myname.net.": ips("100.101.101.101"),
					"foo.com.":    ips("1.2.3.4"),
					"bar.com.":    ips("1::6"),
				},
			},
		},
		{
			name: "corp_dns_misc",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name: "host.some.domain.net.",
				}).View(),
				DNS: tailcfg.DNSConfig{
					Proxied: true,
					Domains: []string{"foo.com", "bar.com"},
				},
			},
			prefs: &ipn.Prefs{
				CorpDNS: true,
			},
			want: &dns.Config{
				AcceptDNS: true,
				Hosts:     map[dnsname.FQDN][]netip.Addr{},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{
					"0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.": nil,
					"100.100.in-addr.arpa.":             nil,
					"101.100.in-addr.arpa.":             nil,
					"102.100.in-addr.arpa.":             nil,
					"103.100.in-addr.arpa.":             nil,
					"104.100.in-addr.arpa.":             nil,
					"105.100.in-addr.arpa.":             nil,
					"106.100.in-addr.arpa.":             nil,
					"107.100.in-addr.arpa.":             nil,
					"108.100.in-addr.arpa.":             nil,
					"109.100.in-addr.arpa.":             nil,
					"110.100.in-addr.arpa.":             nil,
					"111.100.in-addr.arpa.":             nil,
					"112.100.in-addr.arpa.":             nil,
					"113.100.in-addr.arpa.":             nil,
					"114.100.in-addr.arpa.":             nil,
					"115.100.in-addr.arpa.":             nil,
					"116.100.in-addr.arpa.":             nil,
					"117.100.in-addr.arpa.":             nil,
					"118.100.in-addr.arpa.":             nil,
					"119.100.in-addr.arpa.":             nil,
					"120.100.in-addr.arpa.":             nil,
					"121.100.in-addr.arpa.":             nil,
					"122.100.in-addr.arpa.":             nil,
					"123.100.in-addr.arpa.":             nil,
					"124.100.in-addr.arpa.":             nil,
					"125.100.in-addr.arpa.":             nil,
					"126.100.in-addr.arpa.":             nil,
					"127.100.in-addr.arpa.":             nil,
					"64.100.in-addr.arpa.":              nil,
					"65.100.in-addr.arpa.":              nil,
					"66.100.in-addr.arpa.":              nil,
					"67.100.in-addr.arpa.":              nil,
					"68.100.in-addr.arpa.":              nil,
					"69.100.in-addr.arpa.":              nil,
					"70.100.in-addr.arpa.":              nil,
					"71.100.in-addr.arpa.":              nil,
					"72.100.in-addr.arpa.":              nil,
					"73.100.in-addr.arpa.":              nil,
					"74.100.in-addr.arpa.":              nil,
					"75.100.in-addr.arpa.":              nil,
					"76.100.in-addr.arpa.":              nil,
					"77.100.in-addr.arpa.":              nil,
					"78.100.in-addr.arpa.":              nil,
					"79.100.in-addr.arpa.":              nil,
					"80.100.in-addr.arpa.":              nil,
					"81.100.in-addr.arpa.":              nil,
					"82.100.in-addr.arpa.":              nil,
					"83.100.in-addr.arpa.":              nil,
					"84.100.in-addr.arpa.":              nil,
					"85.100.in-addr.arpa.":              nil,
					"86.100.in-addr.arpa.":              nil,
					"87.100.in-addr.arpa.":              nil,
					"88.100.in-addr.arpa.":              nil,
					"89.100.in-addr.arpa.":              nil,
					"90.100.in-addr.arpa.":              nil,
					"91.100.in-addr.arpa.":              nil,
					"92.100.in-addr.arpa.":              nil,
					"93.100.in-addr.arpa.":              nil,
					"94.100.in-addr.arpa.":              nil,
					"95.100.in-addr.arpa.":              nil,
					"96.100.in-addr.arpa.":              nil,
					"97.100.in-addr.arpa.":              nil,
					"98.100.in-addr.arpa.":              nil,
					"99.100.in-addr.arpa.":              nil,
					"some.domain.net.":                  nil,
				},
				SearchDomains: []dnsname.FQDN{
					"foo.com.",
					"bar.com.",
				},
			},
		},
		{
			// Prior to fixing https://github.com/tailscale/tailscale/issues/2116,
			// Android had cases where it needed FallbackResolvers. This was the
			// negative test for the case where Override-local-DNS was set, so the
			// fallback resolvers did not need to be used. This test is still valid
			// so we keep it, but the fallback test has been removed.
			name: "android_does_NOT_need_fallbacks",
			os:   "android",
			nm: &netmap.NetworkMap{
				DNS: tailcfg.DNSConfig{
					Resolvers: []*dnstype.Resolver{
						{Addr: "8.8.8.8"},
					},
					FallbackResolvers: []*dnstype.Resolver{
						{Addr: "8.8.4.4"},
					},
					Routes: map[string][]*dnstype.Resolver{
						"foo.com.": {{Addr: "1.2.3.4"}},
					},
				},
			},
			prefs: &ipn.Prefs{
				CorpDNS: true,
			},
			want: &dns.Config{
				AcceptDNS: true,
				Hosts:     map[dnsname.FQDN][]netip.Addr{},
				DefaultResolvers: []*dnstype.Resolver{
					{Addr: "8.8.8.8"},
				},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{
					"foo.com.": {{Addr: "1.2.3.4"}},
				},
			},
		},
		{
			name: "exit_nodes_need_fallbacks",
			nm: &netmap.NetworkMap{
				DNS: tailcfg.DNSConfig{
					FallbackResolvers: []*dnstype.Resolver{
						{Addr: "8.8.4.4"},
					},
				},
			},
			prefs: &ipn.Prefs{
				CorpDNS:    true,
				ExitNodeID: "some-id",
			},
			want: &dns.Config{
				AcceptDNS: true,
				Hosts:     map[dnsname.FQDN][]netip.Addr{},
				Routes:    map[dnsname.FQDN][]*dnstype.Resolver{},
				DefaultResolvers: []*dnstype.Resolver{
					{Addr: "8.8.4.4"},
				},
			},
		},
		{
			name: "not_exit_node_NOT_need_fallbacks",
			nm: &netmap.NetworkMap{
				DNS: tailcfg.DNSConfig{
					FallbackResolvers: []*dnstype.Resolver{
						{Addr: "8.8.4.4"},
					},
				},
			},
			prefs: &ipn.Prefs{
				CorpDNS: true,
			},
			want: &dns.Config{
				AcceptDNS: true,
				Hosts:     map[dnsname.FQDN][]netip.Addr{},
				Routes:    map[dnsname.FQDN][]*dnstype.Resolver{},
			},
		},
		{
			name: "self_expired",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name:      "myname.net.",
					Addresses: ipps("100.101.101.101"),
				}).View(),
			},
			expired: true,
			peers: nodeViews([]*tailcfg.Node{
				{
					ID:        1,
					Name:      "peera.net",
					Addresses: ipps("100.102.0.1", "100.102.0.2", "fe75::1001", "fe75::1002"),
				},
			}),
			prefs: &ipn.Prefs{},
			want:  &dns.Config{},
		},
		{
			name: "conn25-split-dns",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name:      "a",
					Addresses: ipps("100.101.101.101"),
					CapMap: tailcfg.NodeCapMap{
						tailcfg.NodeCapability(appc.AppConnectorsExperimentalAttrName): []tailcfg.RawMessage{
							tailcfg.RawMessage(`{"name":"app1","connectors":["tag:woo"],"domains":["example.com"]}`),
						},
					},
				}).View(),
				AllCaps: set.Of(tailcfg.NodeCapability(appc.AppConnectorsExperimentalAttrName)),
			},
			peers: nodeViews([]*tailcfg.Node{
				{
					ID:        1,
					Name:      "p1",
					Addresses: ipps("100.102.0.1"),
					Tags:      []string{"tag:woo"},
					Hostinfo: (&tailcfg.Hostinfo{
						Services: []tailcfg.Service{
							{
								Proto: tailcfg.PeerAPI4,
								Port:  1234,
							},
						},
						AppConnector: opt.NewBool(true),
					}).View(),
				},
			}),
			prefs: &ipn.Prefs{
				CorpDNS: true,
			},
			want: &dns.Config{
				AcceptDNS: true,
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"a.":  ips("100.101.101.101"),
					"p1.": ips("100.102.0.1"),
				},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{
					dnsname.FQDN("example.com."): {
						{Addr: "http://100.102.0.1:1234/dns-query"},
					},
				},
			},
		},
		{
			name: "conn25-split-dns-no-matching-peers",
			nm: &netmap.NetworkMap{
				SelfNode: (&tailcfg.Node{
					Name:      "a",
					Addresses: ipps("100.101.101.101"),
					CapMap: tailcfg.NodeCapMap{
						tailcfg.NodeCapability(appc.AppConnectorsExperimentalAttrName): []tailcfg.RawMessage{
							tailcfg.RawMessage(`{"name":"app1","connectors":["tag:woo"],"domains":["example.com"]}`),
						},
					},
				}).View(),
				AllCaps: set.Of(tailcfg.NodeCapability(appc.AppConnectorsExperimentalAttrName)),
			},
			peers: nodeViews([]*tailcfg.Node{
				{
					ID:        1,
					Name:      "p1",
					Addresses: ipps("100.102.0.1"),
					Tags:      []string{"tag:nomatch"},
					Hostinfo: (&tailcfg.Hostinfo{
						Services: []tailcfg.Service{
							{
								Proto: tailcfg.PeerAPI4,
								Port:  1234,
							},
						},
						AppConnector: opt.NewBool(true),
					}).View(),
				},
			}),
			prefs: &ipn.Prefs{
				CorpDNS: true,
			},
			want: &dns.Config{
				AcceptDNS: true,
				Routes:    map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts: map[dnsname.FQDN][]netip.Addr{
					"a.":  ips("100.101.101.101"),
					"p1.": ips("100.102.0.1"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verOS := cmp.Or(tt.os, "linux")
			var log tstest.MemLogger
			got := dnsConfigForNetmap(tt.nm, peersMap(tt.peers), tt.prefs.View(), tt.expired, log.Logf, verOS)
			if !reflect.DeepEqual(got, tt.want) {
				gotj, _ := json.MarshalIndent(got, "", "\t")
				wantj, _ := json.MarshalIndent(tt.want, "", "\t")
				t.Errorf("wrong\n got: %s\n\nwant: %s\n", gotj, wantj)
			}
			if got := log.String(); got != tt.wantLog {
				t.Errorf("log output wrong\n got: %q\nwant: %q\n", got, tt.wantLog)
			}
		})
	}
}

func peersMap(s []tailcfg.NodeView) map[tailcfg.NodeID]tailcfg.NodeView {
	m := make(map[tailcfg.NodeID]tailcfg.NodeView)
	for _, n := range s {
		if n.ID() == 0 {
			panic("zero Node.ID")
		}
		m[n.ID()] = n
	}
	return m
}

func TestAllowExitNodeDNSProxyToServeName(t *testing.T) {
	b := newTestLocalBackend(t)
	if b.allowExitNodeDNSProxyToServeName("google.com") {
		t.Fatal("unexpected true on backend with nil NetMap")
	}

	b.currentNode().SetNetMap(&netmap.NetworkMap{
		DNS: tailcfg.DNSConfig{
			ExitNodeFilteredSet: []string{
				".ts.net",
				"some.exact.bad",
			},
		},
	})
	tests := []struct {
		name string
		want bool
	}{
		// Allow by default:
		{"google.com", true},
		{"GOOGLE.com", true},

		// Rejected by suffix:
		{"foo.TS.NET", false},
		{"foo.ts.net", false},

		// Suffix doesn't match
		{"ts.net", true},

		// Rejected by exact match:
		{"some.exact.bad", false},
		{"SOME.EXACT.BAD", false},

		// But a prefix is okay.
		{"prefix-okay.some.exact.bad", true},
	}
	for _, tt := range tests {
		got := b.allowExitNodeDNSProxyToServeName(tt.name)
		if got != tt.want {
			t.Errorf("for %q = %v; want %v", tt.name, got, tt.want)
		}
	}

}

// mkResolver builds a [dnstype.Resolver] with optional bootstrap IPs. Used by the split-DNS filter tests.
func mkResolver(addr string, bootstrap ...string) *dnstype.Resolver {
	r := &dnstype.Resolver{Addr: addr}
	for _, b := range bootstrap {
		r.BootstrapResolution = append(r.BootstrapResolution, netip.MustParseAddr(b))
	}
	return r
}

// TestFilterUnreachableSplitDNS exercises the per-resolver reachability filter against a richly-loaded multi-peer netmap that covers every input shape and reachability source the filter sees in practice. One suffix (example.com) carries the bulk of the resolvers so partial-drop assertions verify each lookup path in a single pass; a second suffix (all-dropped.tailnet) has only an unreachable resolver to exercise full-suffix removal.
//
// Tailnet shape ("company.ts.net"):
//   - self: own CGNAT + ULA address, an approved 10.99.0.0/24 subnet in AllowedIPs, and two unapproved-but-advertised 4via6 prefixes in Hostinfo.RoutableIPs (netstack handles these as loopback even pre-approval, per #12016).
//   - office-coredns: CGNAT-only peer.
//   - subnet-router: holds only fd7a:115c:a1e0:b1a:0:1:a00:0/104 in cfg.Peers -- 4via6 SiteID=1 covering IPv4 10.0.0.0/8.
//   - dual-stack-host: CGNAT + tailnet-ULA, both routed in cfg.Peers.
//   - invisible-peer: in nm.Peers (so hostname lookup finds it) but absent from cfg.Peers because no grant exposes it to the local node.
func TestFilterUnreachableSplitDNS(t *testing.T) {
	const magicSuffix = "company.ts.net"

	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			Name:      "self." + magicSuffix + ".",
			Addresses: ipps("100.97.96.172", "fd7a:115c:a1e0::c83a:307a"),
			// AllowedIPs is the union of own addresses and *approved* advertised routes.
			AllowedIPs: ipps("100.97.96.172", "fd7a:115c:a1e0::c83a:307a", "10.99.0.0/24"),
			Hostinfo: (&tailcfg.Hostinfo{
				// RoutableIPs is everything advertised, approved or not. The two 4via6 prefixes below are intentionally *not* in AllowedIPs above (control hasn't approved them) -- the filter must still treat them as reachable because netstack handles them as loopback.
				RoutableIPs: []netip.Prefix{
					netip.MustParsePrefix("10.99.0.0/24"),
					netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1337:808:808/128"),
					netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1338::/96"),
				},
			}).View(),
		}).View(),
		DNS: tailcfg.DNSConfig{
			ExtraRecords: []tailcfg.DNSRecord{
				// Extra-only hostname pointing at a routed peer IP.
				{Name: "coredns-extra.company.ts.net", Value: "100.64.0.10"},
				// Same name as the dual-stack-host peer but pointing at an unrouted IP. Peer's real IPs must win, otherwise the unrouted IP would (incorrectly) filter the resolver.
				{Name: "dual-stack-host.company.ts.net", Value: "100.96.0.99"},
				// Non-empty Type: skipped.
				{Name: "skip-me.company.ts.net", Type: "AAAA", Value: "fd7a:115c:a1e0::dead"},
			},
		},
	}
	addPeer := func(id tailcfg.NodeID, name string, ips ...string) {
		nm.Peers = append(nm.Peers, (&tailcfg.Node{
			ID:        id,
			Name:      name + "." + magicSuffix + ".",
			Addresses: ipps(ips...),
		}).View())
	}
	addPeer(1, "office-coredns", "100.64.0.10")
	addPeer(2, "subnet-router", "100.64.0.20", "fd7a:115c:a1e0::20")
	addPeer(3, "dual-stack-host", "100.64.0.30", "fd7a:115c:a1e0::30")
	addPeer(4, "invisible-peer", "100.64.0.99") // in nm.Peers; absent from cfg.Peers below (no grant exposes it)

	cfg := &wgcfg.Config{
		Peers: []wgcfg.Peer{
			{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")}},                                                  // office-coredns
			{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("fd7a:115c:a1e0:b1a:0:1:a00:0/104")}},                                // subnet-router 4via6 for 10.0.0.0/8
			{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.30/32"), netip.MustParsePrefix("fd7a:115c:a1e0::30/128")}}, // dual-stack-host
			// invisible-peer intentionally absent (no grant from local node).
		},
	}

	keep := []*dnstype.Resolver{
		mkResolver("100.64.0.10:53"),                                                  // peer (CGNAT, IP:port)
		mkResolver("100.64.0.10"),                                                     // peer (bare IP, no port -- common control-plane form)
		mkResolver("100.97.96.172"),                                                   // self loopback v4
		mkResolver("fd7a:115c:a1e0::c83a:307a"),                                       // self loopback v6
		mkResolver("10.99.0.42"),                                                      // RFC1918: always kept (non-tailnet IP, out of scope)
		mkResolver("8.8.8.8:53"),                                                      // public UDP
		mkResolver("fd7a:115c:a1e0:b1a:0:1337:808:808"),                               // 4via6 advertised + unapproved (netstack-local per #12016)
		mkResolver("[fd7a:115c:a1e0:b1a:0:1338:8efb:d6ce]:53"),                        // inside advertised 4via6 /96
		mkResolver("[fd7a:115c:a1e0:b1a:0:1:a00:5]:53"),                               // 4via6 routed via subnet-router (SiteID 1, encodes 10.0.0.5)
		mkResolver("[fd7a:115c:a1e0::30]:53"),                                         // dual-stack-host v6
		mkResolver("http://100.64.0.10/dns-query"),                                    // URL form with IP literal (routed)
		mkResolver("https://self.company.ts.net/dns-query"),                           // URL hostname -> self loopback
		mkResolver("https://office-coredns.company.ts.net/dns-query"),                 // URL hostname -> peer
		mkResolver("https://OFFICE-COREDNS.Company.TS.NET/dns-query"),                 // case-folded peer lookup
		mkResolver("https://coredns-extra.company.ts.net/dns-query"),                  // URL hostname -> ExtraRecord
		mkResolver("https://dual-stack-host.company.ts.net/dns-query"),                // peer shadows ExtraRecord (peer IPs are routed)
		mkResolver("https://coredns.other.ts.net/dns-query"),                          // non-magic suffix -> out of scope
		mkResolver("https://dns.google/dns-query"),                                    // public hostname -> out of scope
		mkResolver("https://nope.example.com/dns-query", "100.64.0.10"),               // bootstrap: routed
		mkResolver("https://nope.example.com/dns-query", "100.64.0.77", "1.1.1.1"),    // bootstrap: unrouted tailnet IP + public -- public makes it reachable
		mkResolver("https://nope.example.com/dns-query", "100.64.0.77", "100.64.0.10"), // bootstrap: unrouted + routed tailnet -- routed makes it reachable
		mkResolver("https://[invalid"),                                                // malformed Addr: conservatively kept (no IPs to decide on)
	}
	drop := []*dnstype.Resolver{
		mkResolver("100.64.0.77:53"),                                       // CGNAT IP with no peer
		mkResolver("100.64.0.77"),                                          // bare CGNAT, no peer
		mkResolver("fd7a:115c:a1e0::6a3a:dead"),                            // ULA, no peer
		mkResolver("[fd7a:115c:a1e0:b1a:0:2:a00:5]:53"),                    // 4via6 wrong SiteID (no covering route)
		mkResolver("http://100.64.0.77/dns-query"),                         // URL form, unrouted IP literal
		mkResolver("https://invisible-peer.company.ts.net/dns-query"),      // URL hostname -> peer in nm.Peers but not visible to this node (no grant; absent from cfg.Peers)
		mkResolver("https://nosuchhost.company.ts.net/dns-query"),          // magic suffix, unresolvable
		mkResolver("https://nope.example.com/dns-query", "100.64.0.77"),    // bootstrap: only unrouted tailnet IP
	}

	dcfg := &dns.Config{
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{
			// slices.Concat returns a fresh slice so the filter's in-place mutation doesn't disturb keep/drop, which are reused below as expected values.
			dnsname.FQDN("example.com."):         slices.Concat(keep, drop),
			dnsname.FQDN("all-dropped.tailnet."): {mkResolver("100.64.0.77:53")},
		},
	}

	gotFiltered := filterUnreachableSplitDNS(dcfg, cfg, nm)

	wantSurviving := map[string][]*dnstype.Resolver{"example.com": keep}
	wantFiltered := map[string][]*dnstype.Resolver{
		"example.com":         drop,
		"all-dropped.tailnet": {mkResolver("100.64.0.77:53")},
	}

	gotSurviving := map[string][]*dnstype.Resolver{}
	for k, v := range dcfg.Routes {
		gotSurviving[k.WithoutTrailingDot()] = v
	}
	if !reflect.DeepEqual(gotSurviving, wantSurviving) {
		t.Errorf("surviving routes mismatch\n got: %s\nwant: %s", spew(gotSurviving), spew(wantSurviving))
	}
	if !reflect.DeepEqual(gotFiltered, wantFiltered) {
		t.Errorf("filtered mismatch\n got: %s\nwant: %s", spew(gotFiltered), spew(wantFiltered))
	}
}

// TestFilterUnreachableSplitDNS_Edges covers configurations missing setup that the comprehensive scenario assumes (empty resolver lists, no MagicDNSSuffix).
func TestFilterUnreachableSplitDNS_Edges(t *testing.T) {
	tests := []struct {
		name         string
		magicSuffix  string
		inRoutes     map[string][]*dnstype.Resolver
		wantRoutes   map[string][]*dnstype.Resolver
		wantFiltered map[string][]*dnstype.Resolver
	}{
		{
			// Empty resolver list: nothing to filter, suffix preserved as-is.
			name:        "empty_resolver_list_preserved",
			magicSuffix: "foo.ts.net",
			inRoutes:    map[string][]*dnstype.Resolver{"corp.example": {}},
			wantRoutes:  map[string][]*dnstype.Resolver{"corp.example": {}},
		},
		{
			// No MagicDNSSuffix (no SelfNode): the magic-suffix gating step is skipped, so a tailnet-looking hostname with no netmap entry is kept (treated as public/out-of-scope).
			name:        "no_magic_suffix_kept",
			magicSuffix: "",
			inRoutes:    map[string][]*dnstype.Resolver{"corp.example": {mkResolver("https://coredns.foo.ts.net/dns-query")}},
			wantRoutes:  map[string][]*dnstype.Resolver{"corp.example": {mkResolver("https://coredns.foo.ts.net/dns-query")}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nm := &netmap.NetworkMap{}
			if tt.magicSuffix != "" {
				nm.SelfNode = (&tailcfg.Node{Name: "self." + tt.magicSuffix + "."}).View()
			}
			routes := map[dnsname.FQDN][]*dnstype.Resolver{}
			for k, v := range tt.inRoutes {
				routes[dnsname.FQDN(k+".")] = v
			}
			dcfg := &dns.Config{Routes: routes}
			cfg := &wgcfg.Config{}
			gotFiltered := filterUnreachableSplitDNS(dcfg, cfg, nm)

			gotRoutes := map[string][]*dnstype.Resolver{}
			for k, v := range dcfg.Routes {
				gotRoutes[k.WithoutTrailingDot()] = v
			}
			if !reflect.DeepEqual(gotRoutes, tt.wantRoutes) {
				t.Errorf("dcfg.Routes mismatch\n got: %s\nwant: %s", spew(gotRoutes), spew(tt.wantRoutes))
			}
			if !reflect.DeepEqual(gotFiltered, tt.wantFiltered) {
				t.Errorf("filtered mismatch\n got: %s\nwant: %s", spew(gotFiltered), spew(tt.wantFiltered))
			}
		})
	}
}

func spew(m map[string][]*dnstype.Resolver) string {
	if m == nil {
		return "nil"
	}
	b, _ := json.Marshal(m)
	return string(b)
}
