// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package deepprint

import (
	"bytes"
	"testing"

	"inet.af/netaddr"
	"tailscale.com/net/dns"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

func TestDeepPrint(t *testing.T) {
	// v contains the types of values we care about for our current callers.
	// Mostly we're just testing that we don't panic on handled types.
	v := getVal()

	var buf bytes.Buffer
	Print(&buf, v)
	t.Logf("Got: %s", buf.Bytes())

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
			Name:       "foo",
			Addresses:  []netaddr.IPPrefix{{Bits: 5, IP: netaddr.IPFrom16([16]byte{3: 3})}},
			ListenPort: 5,
			Peers: []wgcfg.Peer{
				{
					Endpoints: "foo:5",
				},
			},
		},
		&router.Config{
			DNS: dns.OSConfig{
				Nameservers: []netaddr.IP{netaddr.IPv4(8, 8, 8, 8)},
				Domains:     []string{"tailscale.net"},
			},
		},
		map[string]string{
			"key1": "val1",
			"key2": "val2",
			"key3": "val3",
			"key4": "val4",
			"key5": "val5",
			"key6": "val6",
			"key7": "val7",
			"key8": "val8",
			"key9": "val9",
		},
	}
}
