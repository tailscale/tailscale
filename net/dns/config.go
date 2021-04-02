// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"inet.af/netaddr"
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
	Routes map[string][]netaddr.IPPort
	// SearchDomains are DNS suffixes to try when expanding
	// single-label queries.
	SearchDomains []string
	// Hosts maps DNS FQDNs to their IPs, which can be a mix of IPv4
	// and IPv6.
	// Queries matching entries in Hosts are resolved locally without
	// recursing off-machine.
	Hosts map[string][]netaddr.IP
	// AuthoritativeSuffixes is a list of fully-qualified DNS suffixes
	// for which the in-process Tailscale resolver is authoritative.
	// Queries for names within AuthoritativeSuffixes can only be
	// fulfilled by entries in Hosts. Queries with no match in Hosts
	// return NXDOMAIN.
	AuthoritativeSuffixes []string
}

// OSConfig is an OS DNS configuration.
type OSConfig struct {
	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netaddr.IP
	// Domains are the search domains to use.
	Domains []string
	// Proxied indicates whether DNS requests are proxied through a dns.Resolver.
	// This enables MagicDNS.
	Proxied bool
}

// Equal determines whether its argument and receiver
// represent equivalent DNS configurations (then DNS reconfig is a no-op).
func (lhs OSConfig) Equal(rhs OSConfig) bool {
	if lhs.Proxied != rhs.Proxied {
		return false
	}

	if len(lhs.Nameservers) != len(rhs.Nameservers) {
		return false
	}

	if len(lhs.Domains) != len(rhs.Domains) {
		return false
	}

	// With how we perform resolution order shouldn't matter,
	// but it is unlikely that we will encounter different orders.
	for i, server := range lhs.Nameservers {
		if rhs.Nameservers[i] != server {
			return false
		}
	}

	// The order of domains, on the other hand, is significant.
	for i, domain := range lhs.Domains {
		if rhs.Domains[i] != domain {
			return false
		}
	}

	return true
}
