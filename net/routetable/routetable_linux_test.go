// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package routetable

import (
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGetRouteTable(t *testing.T) {
	routes, err := Get(1000)
	if err != nil {
		t.Fatal(err)
	}

	// Basic assertion: we have at least one 'default' route in the main table
	var (
		hasDefault bool
	)
	for _, route := range routes {
		if route.Dst == defaultRouteIPv4 && route.Sys.(RouteEntryLinux).Table == unix.RT_TABLE_MAIN {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Errorf("expected at least one default route; routes=%v", routes)
	}
}

func TestRouteEntryFormatting(t *testing.T) {
	testCases := []struct {
		re   RouteEntry
		want string
	}{
		{
			re: RouteEntry{
				Family:    4,
				Type:      RouteTypeMulticast,
				Dst:       RouteDestination{Prefix: netip.MustParsePrefix("100.64.0.0/10")},
				Gateway:   netip.MustParseAddr("1.2.3.1"),
				Interface: "tailscale0",
				Sys: RouteEntryLinux{
					Type:     unix.RTN_UNICAST,
					Table:    52,
					Proto:    unix.RTPROT_STATIC,
					Src:      netip.MustParseAddr("1.2.3.4"),
					Priority: 555,
				},
			},
			want: `{Family: IPv4, Type: multicast, Dst: 100.64.0.0/10, Gateway: 1.2.3.1, Interface: tailscale0, Sys: {Type: unicast, Table: 52, Proto: static, Src: 1.2.3.4, Priority: 555}}`,
		},
		{
			re: RouteEntry{
				Family:  4,
				Type:    RouteTypeUnicast,
				Dst:     RouteDestination{Prefix: netip.MustParsePrefix("1.2.3.0/24")},
				Gateway: netip.MustParseAddr("1.2.3.1"),
				Sys: RouteEntryLinux{
					Type:  unix.RTN_UNICAST,
					Table: unix.RT_TABLE_MAIN,
					Proto: unix.RTPROT_BOOT,
				},
			},
			want: `{Family: IPv4, Dst: 1.2.3.0/24, Gateway: 1.2.3.1, Sys: {Type: unicast}}`,
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			got := fmt.Sprint(tc.re)
			if got != tc.want {
				t.Fatalf("RouteEntry.String() = %q; want %q", got, tc.want)
			}
		})
	}
}
