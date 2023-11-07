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
	"net/netip"
	"slices"
	"strings"
	"sync"

	xmaps "golang.org/x/exp/maps"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
)

// RouteAdvertiser is an interface that allows the AppConnector to advertise
// newly discovered routes that need to be served through the AppConnector.
type RouteAdvertiser interface {
	// AdvertiseRoute adds a new route advertisement if the route is not already
	// being advertised.
	AdvertiseRoute(netip.Prefix) error
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
}

// NewAppConnector creates a new AppConnector.
func NewAppConnector(logf logger.Logf, routeAdvertiser RouteAdvertiser) *AppConnector {
	return &AppConnector{
		logf:            logger.WithPrefix(logf, "appc: "),
		routeAdvertiser: routeAdvertiser,
	}
}

// UpdateDomains replaces the current set of configured domains with the
// supplied set of domains. Domains must not contain a trailing dot, and should
// be lower case.
func (e *AppConnector) UpdateDomains(domains []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	var old map[string][]netip.Addr
	old, e.domains = e.domains, make(map[string][]netip.Addr, len(domains))
	for _, d := range domains {
		d = strings.ToLower(d)
		e.domains[d] = old[d]
	}
	e.logf("handling domains: %v", xmaps.Keys(e.domains))
}

// Domains returns the currently configured domain list.
func (e *AppConnector) Domains() views.Slice[string] {
	e.mu.Lock()
	defer e.mu.Unlock()

	return views.SliceOf(xmaps.Keys(e.domains))
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
		if domain[len(domain)-1] == '.' {
			domain = domain[:len(domain)-1]
		}
		domain = strings.ToLower(domain)
		e.logf("[v2] observed DNS response for %s", domain)

		e.mu.Lock()
		addrs, ok := e.domains[domain]
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
		// TODO(raggi): check for existing prefixes
		if err := e.routeAdvertiser.AdvertiseRoute(netip.PrefixFrom(addr, addr.BitLen())); err != nil {
			e.logf("failed to advertise route for %v: %v", addr, err)
			continue
		}
		e.logf("[v2] advertised route for %v: %v", domain, addr)

		e.mu.Lock()
		e.domains[domain] = append(addrs, addr)
		e.mu.Unlock()
	}

}
