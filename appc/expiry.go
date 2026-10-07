// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"maps"
	"net/netip"
	"slices"
	"time"

	"tailscale.com/types/appctype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

func cloneDomainRoutes(domains map[string][]netip.Addr) map[string][]netip.Addr {
	copy := maps.Clone(domains)
	for domain, addrs := range copy {
		copy[domain] = slices.Clone(addrs)
	}
	return copy
}

func cloneDomainExpiry(expiry map[string]map[netip.Addr]time.Time) map[string]map[netip.Addr]time.Time {
	copy := maps.Clone(expiry)
	for domain, addrs := range copy {
		copy[domain] = maps.Clone(addrs)
	}
	return copy
}

// routeExpiryInterval also rounds deadlines, limiting persistence writes for
// repeated observations of a cached DNS answer. Keep the sweep interval fixed
// even when the configured retention is very short.
const routeExpiryInterval = time.Minute

// refreshRouteExpiryLocked extends an association's lifetime, including when
// its route is already known. A shorter subsequent TTL must not shorten the
// lifetime promised by an earlier DNS response to another client.
func (e *AppConnector) refreshRouteExpiryLocked(domain string, addr netip.Addr, ttl time.Duration) bool {
	if e.routeRetention <= 0 {
		return false
	}
	until := e.clock.Now().Add(max(e.routeRetention, ttl))
	// Round up, never down, so rounding cannot shorten a DNS TTL.
	until = until.Truncate(routeExpiryInterval).Add(routeExpiryInterval)
	if !until.After(e.domainExpiry[domain][addr]) {
		return false
	}
	if e.domainExpiry[domain] == nil {
		mak.Set(&e.domainExpiry, domain, make(map[netip.Addr]time.Time))
	}
	e.domainExpiry[domain][addr] = until
	return true
}

// scheduleExpiryLocked schedules one sweep. The sweep shares the configuration
// queue so an old withdrawal cannot overtake a new route advertisement.
func (e *AppConnector) scheduleExpiryLocked() {
	if e.closed {
		return
	}
	e.expiryTimer = e.clock.AfterFunc(routeExpiryInterval, func() {
		e.queue.Add(e.expireRoutes)
	})
}

func (e *AppConnector) expireRoutes() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	now := e.clock.Now()
	expired := set.Set[netip.Addr]{}
	changed := false
	for domain, deadlines := range e.domainExpiry {
		// Filter once per domain: deleting one address at a time is quadratic
		// when a large collection of stale routes expires in the same sweep.
		if addrs, ok := e.domains[domain]; ok {
			e.domains[domain] = slices.DeleteFunc(slices.Clone(addrs), func(addr netip.Addr) bool {
				deadline, ok := deadlines[addr]
				return ok && !deadline.After(now)
			})
		}
		for addr, deadline := range deadlines {
			if deadline.After(now) {
				continue
			}
			expired.Add(addr)
			changed = true
			delete(deadlines, addr)
		}
		if len(deadlines) == 0 {
			delete(e.domainExpiry, domain)
		}
		if len(e.domains[domain]) == 0 && slices.ContainsFunc(e.wildcards, func(wc string) bool { return dnsname.HasSuffix(domain, wc) }) {
			delete(e.domains, domain)
		}
	}
	toRemove := e.unusedRoutesLocked(expired)
	if len(toRemove) > 0 {
		e.updatePub.Publish(appctype.RouteUpdate{Unadvertise: toRemove})
	}
	if changed {
		e.storeRoutesLocked()
	}
	e.scheduleExpiryLocked()
	e.mu.Unlock()

	// Test and legacy advertisers may call back into the connector, so call
	// them without mu. This queue task finishes before any later advertisement.
	if e.routeAdvertiser != nil && len(toRemove) > 0 {
		if err := e.routeAdvertiser.UnadvertiseRoute(toRemove...); err != nil {
			e.logf("failed to unadvertise expired routes: %v", err)
		}
	}
}

// unusedRoutesLocked excludes addresses used by another domain and exact
// control-plane routes. A covering control route is never withdrawn because
// candidates contain only individual addresses.
func (e *AppConnector) unusedRoutesLocked(candidates set.Set[netip.Addr]) []netip.Prefix {
	for _, addrs := range e.domains {
		for _, addr := range addrs {
			candidates.Delete(addr)
		}
	}
	// ObserveDNSResponse records a lifetime before its advertisement runs on
	// the queue. Preserve routes needed by those pending observations too.
	now := e.clock.Now()
	for _, deadlines := range e.domainExpiry {
		for addr, deadline := range deadlines {
			if deadline.After(now) {
				candidates.Delete(addr)
			}
		}
	}
	for _, route := range e.controlRoutes {
		if route.IsSingleIP() {
			candidates.Delete(route.Addr())
		}
	}
	var routes []netip.Prefix
	for addr := range candidates.All() {
		routes = append(routes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return routes
}
