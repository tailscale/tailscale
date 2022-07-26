// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package publicdns

import (
	"net/netip"
	"testing"
)

func TestInit(t *testing.T) {
	for baseKey, baseSet := range DoHIPsOfBase() {
		for _, addr := range baseSet {
			if KnownDoH()[addr] != baseKey {
				t.Errorf("Expected %v to map to %s, got %s", addr, baseKey, KnownDoH()[addr])
			}
		}
	}
}

func TestDohV6(t *testing.T) {
	tests := []struct {
		in      string
		firstIP netip.Addr
		want    bool
	}{
		{"https://cloudflare-dns.com/dns-query", netip.MustParseAddr("2606:4700:4700::1111"), true},
		{"https://dns.google/dns-query", netip.MustParseAddr("2001:4860:4860::8888"), true},
		{"bogus", netip.Addr{}, false},
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			ip, ok := DoHV6(test.in)
			if ok != test.want || ip != test.firstIP {
				t.Errorf("DohV6 got (%v: IPv6 %v) for %v, want (%v: IPv6 %v)", ip, ok, test.in, test.firstIP, test.want)
			}
		})
	}
}
