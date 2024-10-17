// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"cmp"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/netmap"
	"tailscale.com/util/cloudenv"
	"tailscale.com/util/dnsname"
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
				Name: "myname.net",
				SelfNode: (&tailcfg.Node{
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
			// An ephemeral node with only an IPv6 address
			// should get IPv6 records for all its peers,
			// even if they have IPv4.
			name: "v6_only_self",
			nm: &netmap.NetworkMap{
				Name: "myname.net",
				SelfNode: (&tailcfg.Node{
					Addresses: ipps("fe75::1"),
				}).View(),
			},
			peers: nodeViews([]*tailcfg.Node{
				{
					ID:        1,
					Name:      "peera.net",
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
				Name: "myname.net",
				SelfNode: (&tailcfg.Node{
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
				Name: "host.some.domain.net.",
				DNS: tailcfg.DNSConfig{
					Proxied: true,
					Domains: []string{"foo.com", "bar.com"},
				},
			},
			prefs: &ipn.Prefs{
				CorpDNS: true,
			},
			want: &dns.Config{
				Hosts: map[dnsname.FQDN][]netip.Addr{},
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
				Hosts: map[dnsname.FQDN][]netip.Addr{},
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
				Hosts:  map[dnsname.FQDN][]netip.Addr{},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
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
				Hosts:  map[dnsname.FQDN][]netip.Addr{},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
			},
		},
		{
			name: "self_expired",
			nm: &netmap.NetworkMap{
				Name: "myname.net",
				SelfNode: (&tailcfg.Node{
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
	b := &LocalBackend{}
	if b.allowExitNodeDNSProxyToServeName("google.com") {
		t.Fatal("unexpected true on backend with nil NetMap")
	}

	b.netMap = &netmap.NetworkMap{
		DNS: tailcfg.DNSConfig{
			ExitNodeFilteredSet: []string{
				".ts.net",
				"some.exact.bad",
			},
		},
	}
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
