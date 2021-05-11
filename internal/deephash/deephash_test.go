// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package deephash

import (
	"testing"

	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func TestDeepPrint(t *testing.T) {
	// v contains the types of values we care about for our current callers.
	// Mostly we're just testing that we don't panic on handled types.
	v := getVal()

	hash1 := Hash(v)
	t.Logf("hash: %v", hash1)
	for i := 0; i < 20; i++ {
		hash2 := Hash(getVal())
		if hash1 != hash2 {
			t.Error("second hash didn't match")
		}
	}
}

func getVal() []interface{} {
	return []interface{}{
		&wgcfg.Config{
			Name:      "foo",
			Addresses: []netaddr.IPPrefix{{Bits: 5, IP: netaddr.IPFrom16([16]byte{3: 3})}},
			Peers: []wgcfg.Peer{
				{
					Endpoints: "foo:5",
				},
			},
		},
		&router.Config{
			Routes: []netaddr.IPPrefix{
				netaddr.MustParseIPPrefix("1.2.3.0/24"),
				netaddr.MustParseIPPrefix("1234::/64"),
			},
		},
		map[dnsname.FQDN][]netaddr.IP{
			dnsname.FQDN("a."): {netaddr.MustParseIP("1.2.3.4"), netaddr.MustParseIP("4.3.2.1")},
			dnsname.FQDN("b."): {netaddr.MustParseIP("8.8.8.8"), netaddr.MustParseIP("9.9.9.9")},
		},
		map[dnsname.FQDN][]netaddr.IPPort{
			dnsname.FQDN("a."): {netaddr.MustParseIPPort("1.2.3.4:11"), netaddr.MustParseIPPort("4.3.2.1:22")},
			dnsname.FQDN("b."): {netaddr.MustParseIPPort("8.8.8.8:11"), netaddr.MustParseIPPort("9.9.9.9:22")},
		},
		map[tailcfg.DiscoKey]bool{
			{1: 1}: true,
			{1: 2}: false,
		},
	}
}

func BenchmarkHash(b *testing.B) {
	b.ReportAllocs()
	v := getVal()
	for i := 0; i < b.N; i++ {
		Hash(v)
	}
}
