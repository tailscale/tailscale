// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"tailscale.com/net/tsaddr"
)

func validateViaPrefix(ipp netip.Prefix) error {
	if !tsaddr.IsViaPrefix(ipp) {
		return fmt.Errorf("%v is not a 4-in-6 prefix", ipp)
	}
	if ipp.Bits() < (128 - 32) {
		return fmt.Errorf("%v 4-in-6 prefix must be at least a /%v", ipp, 128-32)
	}
	a := ipp.Addr().As16()
	// The first 64 bits of a are the via prefix.
	// The next 32 bits are the "site ID".
	// The last 32 bits are the IPv4.
	//
	// We used to only allow advertising site IDs from 0-255, but we have
	// since relaxed this (as of 2024-01) to allow IDs from 0-65535.
	siteID := binary.BigEndian.Uint32(a[8:12])
	if siteID > 0xFFFF {
		return fmt.Errorf("route %v contains invalid site ID %08x; must be 0xffff or less", ipp, siteID)
	}
	return nil
}

// CalcAdvertiseRoutes calculates the requested routes to be advertised by a node.
// advertiseRoutes is the user-provided, comma-separated list of routes (IP addresses or CIDR prefixes) to advertise.
// advertiseDefaultRoute indicates whether the node should act as an exit node and advertise default routes.
func CalcAdvertiseRoutes(advertiseRoutes string, advertiseDefaultRoute bool) ([]netip.Prefix, error) {
	routeMap := map[netip.Prefix]bool{}
	if advertiseRoutes != "" {
		var default4, default6 bool
		advroutes := strings.Split(advertiseRoutes, ",")
		for _, s := range advroutes {
			ipp, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid IP address or CIDR prefix", s)
			}
			if ipp != ipp.Masked() {
				return nil, fmt.Errorf("%s has non-address bits set; expected %s", ipp, ipp.Masked())
			}
			if tsaddr.IsViaPrefix(ipp) {
				if err := validateViaPrefix(ipp); err != nil {
					return nil, err
				}
			}
			if ipp == tsaddr.AllIPv4() {
				default4 = true
			} else if ipp == tsaddr.AllIPv6() {
				default6 = true
			}
			routeMap[ipp] = true
		}
		if default4 && !default6 {
			return nil, fmt.Errorf("%s advertised without its IPv6 counterpart, please also advertise %s", tsaddr.AllIPv4(), tsaddr.AllIPv6())
		} else if default6 && !default4 {
			return nil, fmt.Errorf("%s advertised without its IPv4 counterpart, please also advertise %s", tsaddr.AllIPv6(), tsaddr.AllIPv4())
		}
	}
	if advertiseDefaultRoute {
		routeMap[tsaddr.AllIPv4()] = true
		routeMap[tsaddr.AllIPv6()] = true
	}
	if len(routeMap) == 0 {
		return nil, nil
	}
	routes := make([]netip.Prefix, 0, len(routeMap))
	for r := range routeMap {
		routes = append(routes, r)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Bits() != routes[j].Bits() {
			return routes[i].Bits() < routes[j].Bits()
		}
		return routes[i].Addr().Less(routes[j].Addr())
	})
	return routes, nil
}
