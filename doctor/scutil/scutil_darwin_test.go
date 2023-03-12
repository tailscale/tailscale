// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package scutil

import (
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

// Example output from a 2022 MacBook Pro with Tailscale installed, slightly
// redacted for length/clarity.
const scutilDnsOutput = `DNS configuration

resolver #1
  search domain[0] : example.ts.net
  search domain[1] : tailscale.com.beta.tailscale.net
  search domain[2] : ts-dns.test
  nameserver[0] : 100.100.100.100
  if_index : 30 (utun3)
  flags    : Supplemental, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 100200

resolver #2
  nameserver[0] : 8.8.8.8
  nameserver[1] : 8.8.4.4
  flags    : Request A records, Request AAAA records
  reach    : 0x00000002 (Reachable)
  order    : 200000

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 8.8.8.8
  nameserver[1] : 8.8.4.4
  if_index : 15 (en0)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00000002 (Reachable)

resolver #2
  search domain[0] : example.ts.net
  search domain[1] : tailscale.com.beta.tailscale.net
  search domain[2] : ts-dns.test
  nameserver[0] : 100.100.100.100
  if_index : 30 (utun3)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00000003 (Reachable,Transient Connection)
`

func TestParseScutilDNS(t *testing.T) {
	info, err := parseScutilDNS(t.Logf, scutilDnsOutput)
	if err != nil {
		t.Fatal(err)
	}

	expected := &dnsInfo{Sections: []*dnsSection{
		{
			Name: "DNS configuration",
			Entries: []*dnsEntry{
				{
					Name: "resolver #1",
					Config: map[string]string{
						"if_index": "30 (utun3)",
						"flags":    "Supplemental, Request A records, Request AAAA records",
						"reach":    "0x00000003 (Reachable,Transient Connection)",
						"order":    "100200",
					},
					ListConfig: map[string][]string{
						"search domain": []string{"example.ts.net", "tailscale.com.beta.tailscale.net", "ts-dns.test"},
						"nameserver":    []string{"100.100.100.100"},
					},
				},
				{
					Name: "resolver #2",
					Config: map[string]string{
						"flags": "Request A records, Request AAAA records",
						"reach": "0x00000002 (Reachable)",
						"order": "200000",
					},
					ListConfig: map[string][]string{
						"nameserver": []string{"8.8.8.8", "8.8.4.4"},
					},
				},
			},
		},
		{
			Name: "DNS configuration (for scoped queries)",
			Entries: []*dnsEntry{
				{
					Name: "resolver #1",
					Config: map[string]string{
						"if_index": "15 (en0)",
						"flags":    "Scoped, Request A records, Request AAAA records",
						"reach":    "0x00000002 (Reachable)",
					},
					ListConfig: map[string][]string{
						"nameserver": []string{"8.8.8.8", "8.8.4.4"},
					},
				},
				{
					Name: "resolver #2",
					Config: map[string]string{
						"if_index": "30 (utun3)",
						"flags":    "Scoped, Request A records, Request AAAA records",
						"reach":    "0x00000003 (Reachable,Transient Connection)",
					},
					ListConfig: map[string][]string{
						"search domain": []string{"example.ts.net", "tailscale.com.beta.tailscale.net", "ts-dns.test"},
						"nameserver":    []string{"100.100.100.100"},
					},
				},
			},
		},
	}}
	if !reflect.DeepEqual(info, expected) {
		t.Errorf("parse mismatch:\ngot: %s\nwant: %s",
			spew.Sdump(info),
			spew.Sdump(expected),
		)
	}
}
