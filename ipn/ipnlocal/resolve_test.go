// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func TestResolveMagicDNS(t *testing.T) {
	b := newTestLocalBackend(t)

	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID:       1,
			Name:     "self.tail-scale.ts.net.",
			Key:      makeNodeKeyFromID(1),
			DiscoKey: makeDiscoKeyFromID(1),
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("100.64.0.1/32"),
				netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
			},
		}).View(),
		Peers: []tailcfg.NodeView{
			(&tailcfg.Node{
				ID:       2,
				Name:     "peer1.tail-scale.ts.net.",
				Key:      makeNodeKeyFromID(2),
				DiscoKey: makeDiscoKeyFromID(2),
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("100.64.0.2/32"),
					netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
				},
			}).View(),
			(&tailcfg.Node{
				ID:       3,
				Name:     "v6only.tail-scale.ts.net.",
				Key:      makeNodeKeyFromID(3),
				DiscoKey: makeDiscoKeyFromID(3),
				Addresses: []netip.Prefix{
					netip.MustParsePrefix("fd7a:115c:a1e0::3/128"),
				},
			}).View(),
		},
		DNS: tailcfg.DNSConfig{
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: "svc-foo.tail-scale.ts.net.", Value: "100.11.22.33"},
			},
		},
	}
	nm.Domain = "tail-scale.ts.net"
	b.currentNode().SetNetMap(nm)

	tests := []struct {
		name    string
		host    string
		network string
		wantIP  string
		wantOK  bool
	}{
		{name: "fqdn", host: "peer1.tail-scale.ts.net", network: "tcp", wantIP: "100.64.0.2", wantOK: true},
		{name: "short_name", host: "peer1", network: "tcp", wantIP: "100.64.0.2", wantOK: true},
		{name: "self_fqdn", host: "self.tail-scale.ts.net", network: "tcp", wantIP: "100.64.0.1", wantOK: true},
		{name: "self_short", host: "self", network: "tcp", wantIP: "100.64.0.1", wantOK: true},
		{name: "tcp4", host: "peer1", network: "tcp4", wantIP: "100.64.0.2", wantOK: true},
		{name: "tcp6", host: "peer1", network: "tcp6", wantIP: "fd7a:115c:a1e0::2", wantOK: true},
		{name: "v6only_tcp", host: "v6only", network: "tcp", wantIP: "fd7a:115c:a1e0::3", wantOK: true},
		{name: "v6only_tcp4_miss", host: "v6only", network: "tcp4", wantOK: false},
		{name: "extra_record", host: "svc-foo.tail-scale.ts.net", network: "tcp", wantIP: "100.11.22.33", wantOK: true},
		{name: "extra_record_tcp6_miss", host: "svc-foo.tail-scale.ts.net", network: "tcp6", wantOK: false},
		{name: "unknown", host: "nope", network: "tcp", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, ok := b.resolveMagicDNS(tt.host, tt.network)
			if ok != tt.wantOK {
				t.Fatalf("resolveMagicDNS(%q, %q): ok=%v, want %v", tt.host, tt.network, ok, tt.wantOK)
			}
			if ok && ip.String() != tt.wantIP {
				t.Fatalf("resolveMagicDNS(%q, %q): ip=%v, want %v", tt.host, tt.network, ip, tt.wantIP)
			}
		})
	}
}
