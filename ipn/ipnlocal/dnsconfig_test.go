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
		prefs   *ipn.Prefs
		want    *dns.Config
		wantLog string
	}{
		{
			name:  "empty",
			nm:    &netmap.NetworkMap{},
			prefs: &ipn.Prefs{},
			want: &dns.Config{
				Routes: map[dnsname.FQDN][]dnstype.Resolver{},
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
				Routes: map[dnsname.FQDN][]dnstype.Resolver{},
				Hosts: map[dnsname.FQDN][]netaddr.IP{
					"b.net.":       ips("100.102.0.1", "100.102.0.2"),
					"myname.net.":  ips("100.101.101.101"),
					"peera.net.":   ips("100.102.0.1", "100.102.0.2"),
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
				Routes: map[dnsname.FQDN][]dnstype.Resolver{},
				Hosts: map[dnsname.FQDN][]netaddr.IP{
					"myname.net.": ips("100.101.101.101"),
					"foo.com.":    ips("1.2.3.4"),
					"bar.com.":    ips("1::6"),
				},
			},
		},
		// TODO(bradfitz): add tests with prefs.CorpDNS set
		// TODO(bradfitz): pass version.OS to func and add Android/etc tests
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var log tstest.MemLogger
			got := dnsConfigForNetmap(tt.nm, tt.prefs, log.Logf)
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
