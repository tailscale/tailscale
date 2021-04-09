// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"sort"

	"inet.af/netaddr"
	"tailscale.com/util/dnsname"
)

// Config is a DNS configuration.
type Config struct {
	// DefaultResolvers are the DNS resolvers to use for DNS names
	// which aren't covered by more specific per-domain routes below.
	// If empty, the OS's default resolvers (the ones that predate
	// Tailscale altering the configuration) are used.
	DefaultResolvers []netaddr.IPPort
	// Routes maps a DNS suffix to the resolvers that should be used
	// for queries that fall within that suffix.
	// If a query doesn't match any entry in Routes, the
	// DefaultResolvers are used.
	Routes map[dnsname.FQDN][]netaddr.IPPort
	// SearchDomains are DNS suffixes to try when expanding
	// single-label queries.
	SearchDomains []dnsname.FQDN
	// Hosts maps DNS FQDNs to their IPs, which can be a mix of IPv4
	// and IPv6.
	// Queries matching entries in Hosts are resolved locally without
	// recursing off-machine.
	Hosts map[dnsname.FQDN][]netaddr.IP
	// AuthoritativeSuffixes is a list of fully-qualified DNS suffixes
	// for which the in-process Tailscale resolver is authoritative.
	// Queries for names within AuthoritativeSuffixes can only be
	// fulfilled by entries in Hosts. Queries with no match in Hosts
	// return NXDOMAIN.
	AuthoritativeSuffixes []dnsname.FQDN
}

// needsAnyResolvers reports whether c requires a resolver to be set
// at the OS level.
func (c Config) needsOSResolver() bool {
	return c.hasDefaultResolvers() || c.hasRoutes() || c.hasHosts()
}

func (c Config) hasRoutes() bool {
	return len(c.Routes) > 0
}

// hasDefaultResolversOnly reports whether the only resolvers in c are
// DefaultResolvers.
func (c Config) hasDefaultResolversOnly() bool {
	return c.hasDefaultResolvers() && !c.hasRoutes() && !c.hasHosts()
}

func (c Config) hasDefaultResolvers() bool {
	return len(c.DefaultResolvers) > 0
}

// singleResolverSet returns the resolvers used by c.Routes if all
// routes use the same resolvers, or nil if multiple sets of resolvers
// are specified.
func (c Config) singleResolverSet() []netaddr.IPPort {
	var first []netaddr.IPPort
	for _, resolvers := range c.Routes {
		if first == nil {
			first = resolvers
			continue
		}
		if !sameIPPorts(first, resolvers) {
			return nil
		}
	}
	return first
}

// hasHosts reports whether c requires resolution of MagicDNS hosts or
// domains.
func (c Config) hasHosts() bool {
	return len(c.Hosts) > 0 || len(c.AuthoritativeSuffixes) > 0
}

// matchDomains returns the list of match suffixes needed by Routes,
// AuthoritativeSuffixes. Hosts is not considered as we assume that
// they're covered by AuthoritativeSuffixes for now.
func (c Config) matchDomains() []dnsname.FQDN {
	ret := make([]dnsname.FQDN, 0, len(c.Routes)+len(c.AuthoritativeSuffixes))
	seen := map[dnsname.FQDN]bool{}
	for _, suffix := range c.AuthoritativeSuffixes {
		if seen[suffix] {
			continue
		}
		ret = append(ret, suffix)
		seen[suffix] = true
	}
	for suffix := range c.Routes {
		if seen[suffix] {
			continue
		}
		ret = append(ret, suffix)
		seen[suffix] = true
	}
	sort.Slice(ret, func(i, j int) bool {
		return ret[i].WithTrailingDot() < ret[j].WithTrailingDot()
	})
	return ret
}

func sameIPPorts(a, b []netaddr.IPPort) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
