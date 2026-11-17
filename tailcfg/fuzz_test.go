// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailcfg

import (
	"net/netip"
	"strings"
	"testing"
)

func FuzzNodeIsRouter(f *testing.F) {
	encodePrefixes := func(f *testing.F, prefixes ...netip.Prefix) string {
		f.Helper()
		out := make([]string, len(prefixes))
		for i, p := range prefixes {
			out[i] = p.String()
		}
		return strings.Join(out, " ")
	}
	decodePrefixes := func(t *testing.T, prefixes string) []netip.Prefix {
		t.Helper()
		var out []netip.Prefix
		for p := range strings.FieldsSeq(prefixes) {
			pfx, err := netip.ParsePrefix(p)
			if err != nil {
				continue // t.Skipf unsupported by go-118-fuzz-build
			}
			out = append(out, pfx)
		}
		return out
	}

	for _, tc := range []struct {
		name       string
		node       Node
		wantRouter bool
	}{
		{
			name: "empty",
			node: Node{},
		},
		{
			name: "plain-ipv4",
			node: Node{
				Addresses:  []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.70.2.3/24")},
			},
		},
		{
			name: "exit-node-ipv4",
			node: Node{
				Addresses:  []netip.Prefix{netip.MustParsePrefix("10.0.1.2/32")},
				AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.70.3.4/24"), netip.MustParsePrefix("0.71.5.6/16")},
			},
			wantRouter: true,
		},
	} {
		addresses := encodePrefixes(f, tc.node.Addresses...)
		allowedIPs := encodePrefixes(f, tc.node.AllowedIPs...)
		f.Logf("addresses=%q allowedIPs=%q", addresses, allowedIPs)
		f.Add(addresses, allowedIPs)
	}

	f.Fuzz(func(t *testing.T, addresses, allowedIPs string) {
		n := Node{
			Addresses:  decodePrefixes(t, addresses),
			AllowedIPs: decodePrefixes(t, allowedIPs),
		}
		if gotN, gotV := n.IsRouter(), n.View().IsRouter(); gotN != gotV {
			t.Errorf("mismatched node %t, view %t; addresses=%q allowedIPs=%q",
				gotN, gotV, addresses, allowedIPs)
		}
	})
}
