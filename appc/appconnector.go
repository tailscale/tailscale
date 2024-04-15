// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package appc implements App Connectors.
// An AppConnector provides DNS domain oriented routing of traffic. An App
// Connector becomes a DNS server for a peer, authoritative for the set of
// configured domains. DNS resolution of the target domain triggers dynamic
// publication of routes to ensure that traffic to the domain is routed through
// the App Connector.
package appc

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"

	xmaps "golang.org/x/exp/maps"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/execqueue"
	"tailscale.com/util/mak"
	"tailscale.com/util/slicesx"
)

// RouteAdvertiser is an interface that allows the AppConnector to advertise
// newly discovered routes that need to be served through the AppConnector.
type RouteAdvertiser interface {
	// AdvertiseRoute adds one or more route advertisements skipping any that
	// are already advertised.
	AdvertiseRoute(...netip.Prefix) error

	// UnadvertiseRoute removes any matching route advertisements.
	UnadvertiseRoute(...netip.Prefix) error
}

// RouteInfo is a data structure used to persist the in memory state of an AppConnector
// so that we can know, even after a restart, which routes came from ACLs and which were
// learned from domains.
type RouteInfo struct {
	// Control is the routes from the 'routes' section of an app connector acl.
	Control []netip.Prefix `json:",omitempty"`
	// Domains are the routes discovered by observing DNS lookups for configured domains.
	Domains map[string][]netip.Addr `json:",omitempty"`
	// Wildcards are the configured DNS lookup domains to observe. When a DNS query matches Wildcards,
	// its result is added to Domains.
	Wildcards []string `json:",omitempty"`
}

// AppConnector is an implementation of an AppConnector that performs
// its function as a subsystem inside of a tailscale node. At the control plane
// side App Connector routing is configured in terms of domains rather than IP
// addresses.
// The AppConnectors responsibility inside tailscaled is to apply the routing
// and domain configuration as supplied in the map response.
// DNS requests for configured domains are observed. If the domains resolve to
// routes not yet served by the AppConnector the local node configuration is
// updated to advertise the new route.
type AppConnector struct {
	logf            logger.Logf
	routeAdvertiser RouteAdvertiser

	// storeRoutesFunc will be called to persist routes if it is not nil.
	storeRoutesFunc func(*RouteInfo) error

	// mu guards the fields that follow
	mu sync.Mutex

	// domains is a map of lower case domain names with no trailing dot, to an
	// ordered list of resolved IP addresses.
	domains map[string][]netip.Addr

	// controlRoutes is the list of routes that were last supplied by control.
	controlRoutes []netip.Prefix

	// wildcards is the list of domain strings that match subdomains.
	wildcards []string

	// queue provides ordering for update operations
	queue execqueue.ExecQueue
}

// NewAppConnector creates a new AppConnector.
func NewAppConnector(logf logger.Logf, routeAdvertiser RouteAdvertiser, routeInfo *RouteInfo, storeRoutesFunc func(*RouteInfo) error) *AppConnector {
	ac := &AppConnector{
		logf:            logger.WithPrefix(logf, "appc: "),
		routeAdvertiser: routeAdvertiser,
		storeRoutesFunc: storeRoutesFunc,
	}
	if routeInfo != nil {
		ac.domains = routeInfo.Domains
		ac.wildcards = routeInfo.Wildcards
		ac.controlRoutes = routeInfo.Control
	}
	return ac
}

// ShouldStoreRoutes returns true if the appconnector was created with the controlknob on
// and is storing its discovered routes persistently.
func (e *AppConnector) ShouldStoreRoutes() bool {
	return e.storeRoutesFunc != nil
}

// storeRoutesLocked takes the current state of the AppConnector and persists it
func (e *AppConnector) storeRoutesLocked() error {
	if !e.ShouldStoreRoutes() {
		return nil
	}
	return e.storeRoutesFunc(&RouteInfo{
		Control:   e.controlRoutes,
		Domains:   e.domains,
		Wildcards: e.wildcards,
	})
}

// ClearRoutes removes all route state from the AppConnector.
func (e *AppConnector) ClearRoutes() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.controlRoutes = nil
	e.domains = nil
	e.wildcards = nil
	return e.storeRoutesLocked()
}

// UpdateDomainsAndRoutes starts an asynchronous update of the configuration
// given the new domains and routes.
func (e *AppConnector) UpdateDomainsAndRoutes(domains []string, routes []netip.Prefix) {
	e.queue.Add(func() {
		// Add the new routes first.
		e.updateRoutes(routes)
		e.updateDomains(domains)
	})
}

// UpdateDomains asynchronously replaces the current set of configured domains
// with the supplied set of domains. Domains must not contain a trailing dot,
// and should be lower case. If the domain contains a leading '*' label it
// matches all subdomains of a domain.
func (e *AppConnector) UpdateDomains(domains []string) {
	e.queue.Add(func() {
		e.updateDomains(domains)
	})
}

// Wait waits for the currently scheduled asynchronous configuration changes to
// complete.
func (e *AppConnector) Wait(ctx context.Context) {
	e.queue.Wait(ctx)
}

func (e *AppConnector) updateDomains(domains []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var oldDomains map[string][]netip.Addr
	oldDomains, e.domains = e.domains, make(map[string][]netip.Addr, len(domains))
	e.wildcards = e.wildcards[:0]
	for _, d := range domains {
		d = strings.ToLower(d)
		if len(d) == 0 {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			e.wildcards = append(e.wildcards, d[2:])
			continue
		}
		e.domains[d] = oldDomains[d]
		delete(oldDomains, d)
	}

	// Ensure that still-live wildcards addresses are preserved as well.
	for d, addrs := range oldDomains {
		for _, wc := range e.wildcards {
			if dnsname.HasSuffix(d, wc) {
				e.domains[d] = addrs
				delete(oldDomains, d)
				break
			}
		}
	}

	// Everything left in oldDomains is a domain we're no longer tracking
	// and if we are storing route info we can unadvertise the routes
	if e.ShouldStoreRoutes() {
		toRemove := []netip.Prefix{}
		for _, addrs := range oldDomains {
			for _, a := range addrs {
				toRemove = append(toRemove, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		if err := e.routeAdvertiser.UnadvertiseRoute(toRemove...); err != nil {
			e.logf("failed to unadvertise routes on domain removal: %v: %v: %v", xmaps.Keys(oldDomains), toRemove, err)
		}
	}

	e.logf("handling domains: %v and wildcards: %v", xmaps.Keys(e.domains), e.wildcards)
}

// updateRoutes merges the supplied routes into the currently configured routes. The routes supplied
// by control for UpdateRoutes are supplemental to the routes discovered by DNS resolution, but are
// also more often whole ranges. UpdateRoutes will remove any single address routes that are now
// covered by new ranges.
func (e *AppConnector) updateRoutes(routes []netip.Prefix) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If there was no change since the last update, no work to do.
	if slices.Equal(e.controlRoutes, routes) {
		return
	}

	if err := e.routeAdvertiser.AdvertiseRoute(routes...); err != nil {
		e.logf("failed to advertise routes: %v: %v", routes, err)
		return
	}

	var toRemove []netip.Prefix

	// If we're storing routes and know e.controlRoutes is a good
	// representation of what should be in AdvertisedRoutes we can stop
	// advertising routes that used to be in e.controlRoutes but are not
	// in routes.
	if e.ShouldStoreRoutes() {
		toRemove = routesWithout(e.controlRoutes, routes)
	}

nextRoute:
	for _, r := range routes {
		for _, addr := range e.domains {
			for _, a := range addr {
				if r.Contains(a) && netip.PrefixFrom(a, a.BitLen()) != r {
					pfx := netip.PrefixFrom(a, a.BitLen())
					toRemove = append(toRemove, pfx)
					continue nextRoute
				}
			}
		}
	}

	if err := e.routeAdvertiser.UnadvertiseRoute(toRemove...); err != nil {
		e.logf("failed to unadvertise routes: %v: %v", toRemove, err)
	}

	e.controlRoutes = routes
	if err := e.storeRoutesLocked(); err != nil {
		e.logf("failed to store route info: %v", err)
	}
}

// Domains returns the currently configured domain list.
func (e *AppConnector) Domains() views.Slice[string] {
	e.mu.Lock()
	defer e.mu.Unlock()

	return views.SliceOf(xmaps.Keys(e.domains))
}

// DomainRoutes returns a map of domains to resolved IP
// addresses.
func (e *AppConnector) DomainRoutes() map[string][]netip.Addr {
	e.mu.Lock()
	defer e.mu.Unlock()

	drCopy := make(map[string][]netip.Addr)
	for k, v := range e.domains {
		drCopy[k] = append(drCopy[k], v...)
	}

	return drCopy
}

// ObserveDNSResponse is a callback invoked by the DNS resolver when a DNS
// response is being returned over the PeerAPI. The response is parsed and
// matched against the configured domains, if matched the routeAdvertiser is
// advised to advertise the discovered route.
func (e *AppConnector) ObserveDNSResponse(res []byte) {
	var p dnsmessage.Parser
	if _, err := p.Start(res); err != nil {
		return
	}
	if err := p.SkipAllQuestions(); err != nil {
		return
	}

	// cnameChain tracks a chain of CNAMEs for a given query in order to reverse
	// a CNAME chain back to the original query for flattening. The keys are
	// CNAME record targets, and the value is the name the record answers, so
	// for www.example.com CNAME example.com, the map would contain
	// ["example.com"] = "www.example.com".
	var cnameChain map[string]string

	// addressRecords is a list of address records found in the response.
	var addressRecords map[string][]netip.Addr

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return
		}

		if h.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				return
			}
			continue
		}

		switch h.Type {
		case dnsmessage.TypeCNAME, dnsmessage.TypeA, dnsmessage.TypeAAAA:
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
			continue

		}

		domain := strings.TrimSuffix(strings.ToLower(h.Name.String()), ".")
		if len(domain) == 0 {
			continue
		}

		if h.Type == dnsmessage.TypeCNAME {
			res, err := p.CNAMEResource()
			if err != nil {
				return
			}
			cname := strings.TrimSuffix(strings.ToLower(res.CNAME.String()), ".")
			if len(cname) == 0 {
				continue
			}
			mak.Set(&cnameChain, cname, domain)
			continue
		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return
			}
			addr := netip.AddrFrom4(r.A)
			mak.Set(&addressRecords, domain, append(addressRecords[domain], addr))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return
			}
			addr := netip.AddrFrom16(r.AAAA)
			mak.Set(&addressRecords, domain, append(addressRecords[domain], addr))
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
			continue
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for domain, addrs := range addressRecords {
		domain, isRouted := e.findRoutedDomainLocked(domain, cnameChain)

		// domain and none of the CNAMEs in the chain are routed
		if !isRouted {
			continue
		}

		// advertise each address we have learned for the routed domain, that
		// was not already known.
		var toAdvertise []netip.Prefix
		for _, addr := range addrs {
			if !e.isAddrKnownLocked(domain, addr) {
				toAdvertise = append(toAdvertise, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}

		e.logf("[v2] observed new routes for %s: %s", domain, toAdvertise)
		e.scheduleAdvertisement(domain, toAdvertise...)
	}
}

// starting from the given domain that resolved to an address, find it, or any
// of the domains in the CNAME chain toward resolving it, that are routed
// domains, returning the routed domain name and a bool indicating whether a
// routed domain was found.
// e.mu must be held.
func (e *AppConnector) findRoutedDomainLocked(domain string, cnameChain map[string]string) (string, bool) {
	var isRouted bool
	for {
		_, isRouted = e.domains[domain]
		if isRouted {
			break
		}

		// match wildcard domains
		for _, wc := range e.wildcards {
			if dnsname.HasSuffix(domain, wc) {
				e.domains[domain] = nil
				isRouted = true
				break
			}
		}

		next, ok := cnameChain[domain]
		if !ok {
			break
		}
		domain = next
	}
	return domain, isRouted
}

// isAddrKnownLocked returns true if the address is known to be associated with
// the given domain. Known domain tables are updated for covered routes to speed
// up future matches.
// e.mu must be held.
func (e *AppConnector) isAddrKnownLocked(domain string, addr netip.Addr) bool {
	if e.hasDomainAddrLocked(domain, addr) {
		return true
	}
	for _, route := range e.controlRoutes {
		if route.Contains(addr) {
			// record the new address associated with the domain for faster matching in subsequent
			// requests and for diagnostic records.
			e.addDomainAddrLocked(domain, addr)
			return true
		}
	}
	return false
}

// scheduleAdvertisement schedules an advertisement of the given address
// associated with the given domain.
func (e *AppConnector) scheduleAdvertisement(domain string, routes ...netip.Prefix) {
	e.queue.Add(func() {
		if err := e.routeAdvertiser.AdvertiseRoute(routes...); err != nil {
			e.logf("failed to advertise routes for %s: %v: %v", domain, routes, err)
			return
		}
		e.mu.Lock()
		defer e.mu.Unlock()

		for _, route := range routes {
			if !route.IsSingleIP() {
				continue
			}
			addr := route.Addr()
			if !e.hasDomainAddrLocked(domain, addr) {
				e.addDomainAddrLocked(domain, addr)
				e.logf("[v2] advertised route for %v: %v", domain, addr)
			}
		}
		if err := e.storeRoutesLocked(); err != nil {
			e.logf("failed to store route info: %v", err)
		}
	})
}

// hasDomainAddrLocked returns true if the address has been observed in a
// resolution of domain.
func (e *AppConnector) hasDomainAddrLocked(domain string, addr netip.Addr) bool {
	_, ok := slices.BinarySearchFunc(e.domains[domain], addr, compareAddr)
	return ok
}

// addDomainAddrLocked adds the address to the list of addresses resolved for
// domain and ensures the list remains sorted. Does not attempt to deduplicate.
func (e *AppConnector) addDomainAddrLocked(domain string, addr netip.Addr) {
	e.domains[domain] = append(e.domains[domain], addr)
	slices.SortFunc(e.domains[domain], compareAddr)
}

func compareAddr(l, r netip.Addr) int {
	return l.Compare(r)
}

// routesWithout returns a without b where a and b
// are unsorted slices of netip.Prefix
func routesWithout(a, b []netip.Prefix) []netip.Prefix {
	m := make(map[netip.Prefix]bool, len(b))
	for _, p := range b {
		m[p] = true
	}
	return slicesx.Filter(make([]netip.Prefix, 0, len(a)), a, func(p netip.Prefix) bool {
		return !m[p]
	})
}
