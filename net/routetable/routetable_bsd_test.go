// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || freebsd
// +build darwin freebsd

package routetable

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/net/interfaces"
)

func TestRouteEntryFromMsg(t *testing.T) {
	ifs := map[int]interfaces.Interface{
		1: {
			Interface: &net.Interface{
				Name: "iface0",
			},
		},
		2: {
			Interface: &net.Interface{
				Name: "tailscale0",
			},
		},
	}

	ip4 := func(s string) *route.Inet4Addr {
		ip := netip.MustParseAddr(s)
		return &route.Inet4Addr{IP: ip.As4()}
	}
	ip6 := func(s string) *route.Inet6Addr {
		ip := netip.MustParseAddr(s)
		return &route.Inet6Addr{IP: ip.As16()}
	}
	ip6zone := func(s string, idx int) *route.Inet6Addr {
		ip := netip.MustParseAddr(s)
		return &route.Inet6Addr{IP: ip.As16(), ZoneID: idx}
	}
	link := func(idx int, addr string) *route.LinkAddr {
		if _, found := ifs[idx]; !found {
			panic("index not found")
		}

		ret := &route.LinkAddr{
			Index: idx,
		}
		if addr != "" {
			ret.Addr = make([]byte, 6)
			fmt.Sscanf(addr, "%02x:%02x:%02x:%02x:%02x:%02x",
				&ret.Addr[0],
				&ret.Addr[1],
				&ret.Addr[2],
				&ret.Addr[3],
				&ret.Addr[4],
				&ret.Addr[5],
			)
		}
		return ret
	}

	type testCase struct {
		name string
		msg  *route.RouteMessage
		want RouteEntry
		fail bool
	}

	testCases := []testCase{
		{
			name: "BasicIPv4",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("1.2.3.4"),       // dst
					ip4("1.2.3.1"),       // gateway
					ip4("255.255.255.0"), // netmask
				},
			},
			want: RouteEntry{
				Family:  4,
				Type:    RouteTypeUnicast,
				Dst:     RouteDestination{Prefix: netip.MustParsePrefix("1.2.3.4/24")},
				Gateway: netip.MustParseAddr("1.2.3.1"),
				Sys:     RouteEntryBSD{},
			},
		},
		{
			name: "BasicIPv6",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip6("fd7a:115c:a1e0::"), // dst
					ip6("1234::"),           // gateway
					ip6("ffff:ffff:ffff::"), // netmask
				},
			},
			want: RouteEntry{
				Family:  6,
				Type:    RouteTypeUnicast,
				Dst:     RouteDestination{Prefix: netip.MustParsePrefix("fd7a:115c:a1e0::/48")},
				Gateway: netip.MustParseAddr("1234::"),
				Sys:     RouteEntryBSD{},
			},
		},
		{
			name: "IPv6WithZone",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip6zone("fe80::", 2),         // dst
					ip6("1234::"),                // gateway
					ip6("ffff:ffff:ffff:ffff::"), // netmask
				},
			},
			want: RouteEntry{
				Family:  6,
				Type:    RouteTypeUnicast, // TODO
				Dst:     RouteDestination{Prefix: netip.MustParsePrefix("fe80::/64"), Zone: "tailscale0"},
				Gateway: netip.MustParseAddr("1234::"),
				Sys:     RouteEntryBSD{},
			},
		},
		{
			name: "IPv6WithUnknownZone",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip6zone("fe80::", 4),         // dst
					ip6("1234::"),                // gateway
					ip6("ffff:ffff:ffff:ffff::"), // netmask
				},
			},
			want: RouteEntry{
				Family:  6,
				Type:    RouteTypeUnicast, // TODO
				Dst:     RouteDestination{Prefix: netip.MustParsePrefix("fe80::/64"), Zone: "4"},
				Gateway: netip.MustParseAddr("1234::"),
				Sys:     RouteEntryBSD{},
			},
		},
		{
			name: "DefaultIPv4",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("0.0.0.0"), // dst
					ip4("1.2.3.4"), // gateway
					ip4("0.0.0.0"), // netmask
				},
			},
			want: RouteEntry{
				Family:  4,
				Type:    RouteTypeUnicast,
				Dst:     defaultRouteIPv4,
				Gateway: netip.MustParseAddr("1.2.3.4"),
				Sys:     RouteEntryBSD{},
			},
		},
		{
			name: "DefaultIPv6",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip6("0::"),    // dst
					ip6("1234::"), // gateway
					ip6("0::"),    // netmask
				},
			},
			want: RouteEntry{
				Family:  6,
				Type:    RouteTypeUnicast,
				Dst:     defaultRouteIPv6,
				Gateway: netip.MustParseAddr("1234::"),
				Sys:     RouteEntryBSD{},
			},
		},
		{
			name: "ShortAddrs",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("1.2.3.4"), // dst
				},
			},
			want: RouteEntry{
				Family: 4,
				Type:   RouteTypeUnicast,
				Dst:    RouteDestination{Prefix: netip.MustParsePrefix("1.2.3.4/32")},
				Sys:    RouteEntryBSD{},
			},
		},
		{
			name: "TailscaleIPv4",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("100.64.0.0"), // dst
					link(2, ""),
					ip4("255.192.0.0"), // netmask
				},
			},
			want: RouteEntry{
				Family: 4,
				Type:   RouteTypeUnicast,
				Dst:    RouteDestination{Prefix: netip.MustParsePrefix("100.64.0.0/10")},
				Sys: RouteEntryBSD{
					GatewayInterface: "tailscale0",
					GatewayIdx:       2,
				},
			},
		},
		{
			name: "Flags",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("1.2.3.4"),       // dst
					ip4("1.2.3.1"),       // gateway
					ip4("255.255.255.0"), // netmask
				},
				Flags: unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_UP,
			},
			want: RouteEntry{
				Family:  4,
				Type:    RouteTypeUnicast,
				Dst:     RouteDestination{Prefix: netip.MustParsePrefix("1.2.3.4/24")},
				Gateway: netip.MustParseAddr("1.2.3.1"),
				Sys: RouteEntryBSD{
					Flags:    []string{"gateway", "static", "up"},
					RawFlags: unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_UP,
				},
			},
		},
		{
			name: "SkipNoAddrs",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs:   []route.Addr{},
			},
			fail: true,
		},
		{
			name: "SkipBadVersion",
			msg: &route.RouteMessage{
				Version: 1,
			},
			fail: true,
		},
		{
			name: "SkipBadType",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType + 1,
			},
			fail: true,
		},
		{
			name: "OutputIface",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Index:   1,
				Addrs: []route.Addr{
					ip4("1.2.3.4"), // dst
				},
			},
			want: RouteEntry{
				Family:    4,
				Type:      RouteTypeUnicast,
				Dst:       RouteDestination{Prefix: netip.MustParsePrefix("1.2.3.4/32")},
				Interface: "iface0",
				Sys:       RouteEntryBSD{},
			},
		},
		{
			name: "GatewayMAC",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("100.64.0.0"), // dst
					link(1, "01:02:03:04:05:06"),
					ip4("255.192.0.0"), // netmask
				},
			},
			want: RouteEntry{
				Family: 4,
				Type:   RouteTypeUnicast,
				Dst:    RouteDestination{Prefix: netip.MustParsePrefix("100.64.0.0/10")},
				Sys: RouteEntryBSD{
					GatewayAddr:      "01:02:03:04:05:06",
					GatewayInterface: "iface0",
					GatewayIdx:       1,
				},
			},
		},
	}

	if runtime.GOOS == "darwin" {
		testCases = append(testCases,
			testCase{
				name: "SkipFlags",
				msg: &route.RouteMessage{
					Version: 3,
					Type:    rmExpectedType,
					Addrs: []route.Addr{
						ip4("1.2.3.4"),       // dst
						ip4("1.2.3.1"),       // gateway
						ip4("255.255.255.0"), // netmask
					},
					Flags: unix.RTF_UP | skipFlags,
				},
				fail: true,
			},
			testCase{
				name: "NetmaskAdjust",
				msg: &route.RouteMessage{
					Version: 3,
					Type:    rmExpectedType,
					Flags:   unix.RTF_MULTICAST,
					Addrs: []route.Addr{
						ip6("ff00::"),           // dst
						ip6("1234::"),           // gateway
						ip6("ffff:ffff:ff00::"), // netmask
					},
				},
				want: RouteEntry{
					Family:  6,
					Type:    RouteTypeMulticast,
					Dst:     RouteDestination{Prefix: netip.MustParsePrefix("ff00::/8")},
					Gateway: netip.MustParseAddr("1234::"),
					Sys: RouteEntryBSD{
						Flags:    []string{"multicast"},
						RawFlags: unix.RTF_MULTICAST,
					},
				},
			},
		)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			re, ok := routeEntryFromMsg(ifs, tc.msg)
			if wantOk := !tc.fail; ok != wantOk {
				t.Fatalf("ok = %v; want %v", ok, wantOk)
			}

			if !reflect.DeepEqual(re, tc.want) {
				t.Fatalf("RouteEntry mismatch:\n got: %+v\nwant: %+v", re, tc.want)
			}
		})
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
				Type:      RouteTypeUnicast,
				Dst:       RouteDestination{Prefix: netip.MustParsePrefix("1.2.3.0/24")},
				Interface: "en0",
				Sys: RouteEntryBSD{
					GatewayInterface: "en0",
					Flags:            []string{"static", "up"},
				},
			},
			want: `{Family: IPv4, Dst: 1.2.3.0/24, Interface: en0, Sys: {GatewayInterface: en0, Flags: [static up]}}`,
		},
		{
			re: RouteEntry{
				Family:    6,
				Type:      RouteTypeUnicast,
				Dst:       RouteDestination{Prefix: netip.MustParsePrefix("fd7a:115c:a1e0::/24")},
				Interface: "en0",
				Sys: RouteEntryBSD{
					GatewayIdx: 3,
					Flags:      []string{"static", "up"},
				},
			},
			want: `{Family: IPv6, Dst: fd7a:115c:a1e0::/24, Interface: en0, Sys: {GatewayIdx: 3, Flags: [static up]}}`,
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			got := fmt.Sprint(tc.re)
			if got != tc.want {
				t.Fatalf("RouteEntry.String() mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

func TestGetRouteTable(t *testing.T) {
	routes, err := Get(1000)
	if err != nil {
		t.Fatal(err)
	}

	// Basic assertion: we have at least one 'default' route
	var (
		hasDefault bool
	)
	for _, route := range routes {
		if route.Dst == defaultRouteIPv4 || route.Dst == defaultRouteIPv6 {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Errorf("expected at least one default route; routes=%v", routes)
	}
}
