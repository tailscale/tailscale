// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsdns

import (
	"testing"

	"inet.af/netaddr"
)

func TestPretty(t *testing.T) {
	tests := []struct {
		name string
		dmap *Map
		want string
	}{
		{"empty", NewMap(nil, nil), ""},
		{
			"single",
			NewMap(map[string]netaddr.IP{
				"hello.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
			}, nil),
			"hello.ipn.dev.\t100.101.102.103\n",
		},
		{
			"multiple",
			NewMap(map[string]netaddr.IP{
				"test1.domain.":     netaddr.IPv4(100, 101, 102, 103),
				"test2.sub.domain.": netaddr.IPv4(100, 99, 9, 1),
			}, nil),
			"test1.domain.\t100.101.102.103\ntest2.sub.domain.\t100.99.9.1\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dmap.Pretty()
			if tt.want != got {
				t.Errorf("want %v; got %v", tt.want, got)
			}
		})
	}
}

func TestPrettyDiffFrom(t *testing.T) {
	tests := []struct {
		name string
		map1 *Map
		map2 *Map
		want string
	}{
		{
			"from_empty",
			nil,
			NewMap(map[string]netaddr.IP{
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
				"test2.ipn.dev.": netaddr.IPv4(100, 103, 102, 101),
			}, nil),
			"+test1.ipn.dev.\t100.101.102.103\n+test2.ipn.dev.\t100.103.102.101\n",
		},
		{
			"equal",
			NewMap(map[string]netaddr.IP{
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
				"test2.ipn.dev.": netaddr.IPv4(100, 103, 102, 101),
			}, nil),
			NewMap(map[string]netaddr.IP{
				"test2.ipn.dev.": netaddr.IPv4(100, 103, 102, 101),
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
			}, nil),
			"",
		},
		{
			"changed_ip",
			NewMap(map[string]netaddr.IP{
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
				"test2.ipn.dev.": netaddr.IPv4(100, 103, 102, 101),
			}, nil),
			NewMap(map[string]netaddr.IP{
				"test2.ipn.dev.": netaddr.IPv4(100, 104, 102, 101),
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
			}, nil),
			"-test2.ipn.dev.\t100.103.102.101\n+test2.ipn.dev.\t100.104.102.101\n",
		},
		{
			"new_domain",
			NewMap(map[string]netaddr.IP{
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
				"test2.ipn.dev.": netaddr.IPv4(100, 103, 102, 101),
			}, nil),
			NewMap(map[string]netaddr.IP{
				"test3.ipn.dev.": netaddr.IPv4(100, 105, 106, 107),
				"test2.ipn.dev.": netaddr.IPv4(100, 103, 102, 101),
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
			}, nil),
			"+test3.ipn.dev.\t100.105.106.107\n",
		},
		{
			"gone_domain",
			NewMap(map[string]netaddr.IP{
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
				"test2.ipn.dev.": netaddr.IPv4(100, 103, 102, 101),
			}, nil),
			NewMap(map[string]netaddr.IP{
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
			}, nil),
			"-test2.ipn.dev.\t100.103.102.101\n",
		},
		{
			"mixed",
			NewMap(map[string]netaddr.IP{
				"test1.ipn.dev.": netaddr.IPv4(100, 101, 102, 103),
				"test4.ipn.dev.": netaddr.IPv4(100, 107, 106, 105),
				"test5.ipn.dev.": netaddr.IPv4(100, 64, 1, 1),
				"test2.ipn.dev.": netaddr.IPv4(100, 103, 102, 101),
			}, nil),
			NewMap(map[string]netaddr.IP{
				"test2.ipn.dev.": netaddr.IPv4(100, 104, 102, 101),
				"test1.ipn.dev.": netaddr.IPv4(100, 100, 101, 102),
				"test3.ipn.dev.": netaddr.IPv4(100, 64, 1, 1),
			}, nil),
			"-test1.ipn.dev.\t100.101.102.103\n+test1.ipn.dev.\t100.100.101.102\n" +
				"-test2.ipn.dev.\t100.103.102.101\n+test2.ipn.dev.\t100.104.102.101\n" +
				"+test3.ipn.dev.\t100.64.1.1\n-test4.ipn.dev.\t100.107.106.105\n-test5.ipn.dev.\t100.64.1.1\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.map2.PrettyDiffFrom(tt.map1)
			if tt.want != got {
				t.Errorf("want %v; got %v", tt.want, got)
			}
		})
	}
}
