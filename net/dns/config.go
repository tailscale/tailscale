// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"inet.af/netaddr"

	"tailscale.com/types/logger"
)

// Config is the set of parameters that uniquely determine
// the state to which a manager should bring system DNS settings.
type Config struct {
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
func (lhs Config) Equal(rhs Config) bool {
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

// ManagerConfig is the set of parameters from which
// a manager implementation is chosen and initialized.
type ManagerConfig struct {
	// Logf is the logger for the manager to use.
	// It is wrapped with a "dns: " prefix.
	Logf logger.Logf
	// InterfaceName is the name of the interface with which DNS settings should be associated.
	InterfaceName string
}
