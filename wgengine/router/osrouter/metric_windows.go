// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"net/netip"

	"tailscale.com/net/tsaddr"
)

// windowsSubnetRouteMetric is an intentionally "high" route metric used for
// non-Tailscale routes (e.g. advertised subnet routes) on Windows.
//
// Rationale: when a Windows client is physically on a LAN that's also
// advertised via a subnet router, Windows may otherwise prefer the Tailscale
// route due to a low Tailscale interface metric, resulting in local traffic
// being sent to (and dependent on) the subnet router.
//
// See https://github.com/tailscale/tailscale/issues/12248.
const windowsSubnetRouteMetric = uint32(5000)

// windowsRouteMetric returns the route metric to use when installing routes on
// Windows.
//
// For exit-node default routes and single-host Tailscale routes, we keep the
// metric low so the routes behave as expected. For advertised subnet routes, we
// set a higher metric so on-link / locally-connected routes win when present.
func windowsRouteMetric(route netip.Prefix) uint32 {
	if !route.IsValid() {
		return 0
	}
	// Default route (exit node) should stay preferred when configured.
	if route.Bits() == 0 {
		return 0
	}
	// Single-host Tailscale routes should stay preferred.
	if route.IsSingleIP() && tsaddr.IsTailscaleIP(route.Addr().Unmap()) {
		return 0
	}
	// Everything else (notably: advertised subnet routes) should not override
	// on-link routes with the same prefix.
	return windowsSubnetRouteMetric
}

