// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appctest

import (
	"net/netip"
	"slices"
)

// RouteCollector is a test helper that collects the list of routes advertised
type RouteCollector struct {
	routes []netip.Prefix
}

func (rc *RouteCollector) AdvertiseRoute(pfx ...netip.Prefix) error {
	rc.routes = append(rc.routes, pfx...)
	return nil
}

func (rc *RouteCollector) UnadvertiseRoute(toRemove ...netip.Prefix) error {
	routes := rc.routes
	rc.routes = rc.routes[:0]
	for _, r := range routes {
		if !slices.Contains(toRemove, r) {
			rc.routes = append(rc.routes, r)
		}
	}
	return nil
}

// Routes returns the ordered list of routes that were added, including
// possible duplicates.
func (rc *RouteCollector) Routes() []netip.Prefix {
	return rc.routes
}

func (rc *RouteCollector) SetRoutes(routes []netip.Prefix) error {
	rc.routes = routes
	return nil
}
