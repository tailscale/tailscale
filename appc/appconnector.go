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
)

// RouteAdvertiser is an interface that allows the AppConnector to advertise
// newly discovered routes that need to be served through the AppConnector.
type RouteAdvertiser interface {
	// AdvertiseRoute adds a new route advertisement if the route is not already
	// being advertised.
	AdvertiseRoute(netip.Prefix) error

	// UnadvertiseRoute removes a route advertisement.
	UnadvertiseRoute(netip.Prefix) error
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

	// mu guards the fields that follow
	mu sync.Mutex

	// domains is a map of lower case domain names with no trailing dot, to a
	// list of resolved IP addresses.
	domains map[string][]netip.Addr

	// controlRoutes is the list of routes that were last supplied by control.
	controlRoutes []netip.Prefix

	// wildcards is the list of domain strings that match subdomains.
	wildcards []string

	// queue provides ordering for update operations
	queue execqueue.ExecQueue
}

// NewAppConnector creates a new AppConnector.
func NewAppConnector(logf logger.Logf, routeAdvertiser RouteAdvertiser) *AppConnector {
	return &AppConnector{
		logf:            logger.WithPrefix(logf, "appc: "),
		routeAdvertiser: routeAdvertiser,
	}
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
				break
			}
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

nextRoute:
	for _, r := range routes {
		if err := e.routeAdvertiser.AdvertiseRoute(r); err != nil {
			e.logf("failed to advertise route: %v: %v", r, err)
			continue
		}

		for _, addr := range e.domains {
			for _, a := range addr {
				if r.Contains(a) {
					pfx := netip.PrefixFrom(a, a.BitLen())
					if err := e.routeAdvertiser.UnadvertiseRoute(pfx); err != nil {
						e.logf("failed to unadvertise route: %v: %v", pfx, err)
					}
					continue nextRoute
				}
			}
		}
	}

	e.controlRoutes = routes
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

nextAnswer:
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
		if h.Type != dnsmessage.TypeA && h.Type != dnsmessage.TypeAAAA {
			if err := p.SkipAnswer(); err != nil {
				return
			}
			continue
		}

		domain := h.Name.String()
		if len(domain) == 0 {
			return
		}
		domain = strings.TrimSuffix(domain, ".")
		domain = strings.ToLower(domain)
		e.logf("[v2] observed DNS response for %s", domain)

		e.mu.Lock()
		addrs, ok := e.domains[domain]
		// match wildcard domains
		if !ok {
			for _, wc := range e.wildcards {
				if dnsname.HasSuffix(domain, wc) {
					e.domains[domain] = nil
					ok = true
					break
				}
			}
		}
		e.mu.Unlock()

		if !ok {
			if err := p.SkipAnswer(); err != nil {
				return
			}
			continue
		}

		var addr netip.Addr
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return
			}
			addr = netip.AddrFrom4(r.A)
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return
			}
			addr = netip.AddrFrom16(r.AAAA)
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
			continue
		}
		if slices.Contains(addrs, addr) {
			continue
		}
		for _, route := range e.controlRoutes {
			if route.Contains(addr) {
				// record the new address associated with the domain for faster matching in subsequent
				// requests and for diagnostic records.
				e.mu.Lock()
				e.domains[domain] = append(addrs, addr)
				e.mu.Unlock()
				continue nextAnswer
			}
		}
		if err := e.routeAdvertiser.AdvertiseRoute(netip.PrefixFrom(addr, addr.BitLen())); err != nil {
			e.logf("failed to advertise route for %s: %v: %v", domain, addr, err)
			continue
		}
		e.logf("[v2] advertised route for %v: %v", domain, addr)

		e.mu.Lock()
		e.domains[domain] = append(addrs, addr)
		e.mu.Unlock()
	}
}
