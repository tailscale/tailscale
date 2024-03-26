// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package routeinfo

import (
	"net/netip"
	"time"
)

type RouteInfo struct {
	// routes set with --advertise-routes
	Local []netip.Prefix
	// routes from the 'routes' section of an app connector acl
	Control []netip.Prefix
	// routes discovered by observing dns lookups for configured domains
	Discovered map[string]*DatedRoutes
}

type DatedRoutes struct {
	// routes discovered for a domain, and when they were last seen in a dns query
	Routes map[netip.Prefix]time.Time
	// the time at which we last expired old routes
	LastCleanup time.Time
}
