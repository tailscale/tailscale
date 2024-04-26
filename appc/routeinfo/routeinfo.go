// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package routeinfo

import (
	"net/netip"
	"time"
)

type RouteInfo struct {
	// routes from the 'routes' section of an app connector acl
	Control []netip.Prefix
	// routes discovered by observing dns lookups for configured domains
	Discovered map[string]*DatedRoutes

	Wildcards []string
}

func NewRouteInfo() *RouteInfo {
	discovered := make(map[string]*DatedRoutes)
	return &RouteInfo{
		Control:    []netip.Prefix{},
		Discovered: discovered,
		Wildcards:  []string{},
	}
}

// RouteInfo.Routes returns a slice containing all the routes stored from the wanted resources.
func (ri *RouteInfo) Routes(control, discovered bool) []netip.Prefix {
	if ri == nil {
		return []netip.Prefix{}
	}
	var ret []netip.Prefix
	if control && len(ret) == 0 {
		ret = ri.Control
	} else if control {
		ret = append(ret, ri.Control...)
	}

	if discovered {
		for _, dr := range ri.Discovered {
			if dr != nil {
				ret = append(ret, dr.RoutesSlice()...)
			}
		}
	}
	return ret
}

func (ri *RouteInfo) DomainRoutes() map[string][]netip.Addr {
	drCopy := make(map[string][]netip.Addr)
	for k, v := range ri.Discovered {
		drCopy[k] = append(drCopy[k], v.AddrsSlice()...)
	}
	return drCopy
}

type DatedRoutes struct {
	// routes discovered for a domain, and when they were last seen in a dns query
	Routes map[netip.Prefix]time.Time
	// the time at which we last expired old routes
	LastCleanup time.Time
}

func (dr *DatedRoutes) RoutesSlice() []netip.Prefix {
	var routes []netip.Prefix
	for k := range dr.Routes {
		routes = append(routes, k)
	}
	return routes
}

func (dr *DatedRoutes) AddrsSlice() []netip.Addr {
	var routes []netip.Addr
	for k := range dr.Routes {
		if k.IsSingleIP() {
			routes = append(routes, k.Addr())
		}
	}
	return routes
}

func (r *RouteInfo) AddRoutesInDiscoveredForDomain(domain string, addrs []netip.Prefix) {
	dr, hasKey := r.Discovered[domain]
	if !hasKey || dr == nil || dr.Routes == nil {
		newDatedRoutes := &DatedRoutes{make(map[netip.Prefix]time.Time), time.Now()}
		newDatedRoutes.addAddrsToDatedRoute(addrs)
		r.Discovered[domain] = newDatedRoutes
		return
	}

	// kevin comment: we won't see any existing routes here because know addrs are filtered.
	currentRoutes := r.Discovered[domain]
	currentRoutes.addAddrsToDatedRoute(addrs)
	r.Discovered[domain] = currentRoutes
	return
}

func (d *DatedRoutes) addAddrsToDatedRoute(addrs []netip.Prefix) {
	time := time.Now()
	for _, addr := range addrs {
		d.Routes[addr] = time
	}
}
