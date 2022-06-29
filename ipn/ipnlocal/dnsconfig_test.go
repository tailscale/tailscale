// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"encoding/json"
	"reflect"
	"testing"

	"inet.af/netaddr"
	"tailscale.com/ipn"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/netmap"
	"tailscale.com/util/cloudenv"
	"tailscale.com/util/dnsname"
)

func ipps(ippStrs ...string) (ipps []netaddr.IPPrefix) {
	for _, s := range ippStrs {
		if ip, err := netaddr.ParseIP(s); err == nil {
			ipps = append(ipps, netaddr.IPPrefixFrom(ip, ip.BitLen()))
			continue
		}
		ipps = append(ipps, netaddr.MustParseIPPrefix(s))
	}
	return
}

func ips(ss ...string) (ips []netaddr.IP) {
	for _, s := range ss {
		ips = append(ips, netaddr.MustParseIP(s))
	}
	return
}

func TestDNSConfigForNetmap(t *testing.T) {
	tests := []struct {
		name    string
		nm      *netmap.NetworkMap
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
				Hosts:  map[dnsname.FQDN][]netaddr.IP{},
			},
		},
		{
			name: "self_name_and_peers",
			nm: &netmap.NetworkMap{
				Name:      "myname.net",
				Addresses: ipps("100.101.101.101"),
				Peers: []*tailcfg.Node{
					{
						Name:      "peera.net",
						Addresses: ipps("100.102.0.1", "100.102.0.2", "fe75::1001", "fe75::1002"),
					},
					{
						Name:      "b.net",
						Addresses: ipps("100.102.0.1", "100.102.0.2", "fe75::2"),
					},
					{
						Name:      "v6-only.net",
						Addresses: ipps("fe75::3"), // no IPv4, so we don't ignore IPv6
					},
				},
			},
			prefs: &ipn.Prefs{},
			want: &dns.Config{
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts: map[dnsname.FQDN][]netaddr.IP{
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
				Name:      "myname.net",
				Addresses: ipps("fe75::1"),
				Peers: []*tailcfg.Node{
					{
						Name:      "peera.net",
						Addresses: ipps("100.102.0.1", "100.102.0.2", "fe75::1001"),
					},
					{
						Name:      "b.net",
						Addresses: ipps("100.102.0.1", "100.102.0.2", "fe75::2"),
					},
					{
						Name:      "v6-only.net",
						Addresses: ipps("fe75::3"), // no IPv4, so we don't ignore IPv6
					},
				},
			},
			prefs: &ipn.Prefs{},
			want: &dns.Config{
				OnlyIPv6: true,
				Routes:   map[dnsname.FQDN][]*dnstype.Resolver{},
				Hosts: map[dnsname.FQDN][]netaddr.IP{
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
				Name:      "myname.net",
				Addresses: ipps("100.101.101.101"),
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
				Hosts: map[dnsname.FQDN][]netaddr.IP{
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
				Hosts: map[dnsname.FQDN][]netaddr.IP{},
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
				Hosts: map[dnsname.FQDN][]netaddr.IP{},
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
				Hosts:  map[dnsname.FQDN][]netaddr.IP{},
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
				Hosts:  map[dnsname.FQDN][]netaddr.IP{},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
			},
		},
		{
			name: "google_cloud",
			nm: &netmap.NetworkMap{
				DNS: tailcfg.DNSConfig{},
			},
			cloud: cloudenv.GCP,
			prefs: &ipn.Prefs{
				CorpDNS: true,
			},
			want: &dns.Config{
				Hosts: map[dnsname.FQDN][]netaddr.IP{},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{
					"internal.": []*dnstype.Resolver{{Addr: cloudenv.GoogleMetadataAndDNSIP}},
				},
			},
		},
		{
			name: "google_cloud_with_exiting_internal",
			nm: &netmap.NetworkMap{
				DNS: tailcfg.DNSConfig{
					Routes: map[string][]*dnstype.Resolver{
						".internal": []*dnstype.Resolver{{Addr: "1.2.3.4"}},
					},
				},
			},
			cloud: cloudenv.GCP,
			prefs: &ipn.Prefs{
				CorpDNS: true,
			},
			want: &dns.Config{
				Hosts: map[dnsname.FQDN][]netaddr.IP{},
				Routes: map[dnsname.FQDN][]*dnstype.Resolver{
					"internal.": []*dnstype.Resolver{{Addr: "1.2.3.4"}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verOS := tt.os
			if verOS == "" {
				verOS = "linux"
			}
			var log tstest.MemLogger
			got := dnsConfigForNetmap(tt.nm, tt.prefs, log.Logf, verOS, tt.cloud)
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
