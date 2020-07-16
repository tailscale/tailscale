// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"inet.af/netaddr"

	"tailscale.com/types/logger"
)

// Config is the set of parameters which uniquely determine
// the state to which a manager should bring system DNS settings.
type Config struct {
	// Disabled indicates whether DNS settings should be managed at all.
	// If true, active changes are rolled back and all other fields of Config are ignored.
	Disabled bool
	// PerDomain indicates whether it is preferred to use Nameservers
	// only for DNS queries for subdomains of Domains.
	//
	// Note that Nameservers may still be applied to all queries
	// if the manager does not support per-domain settings.
	PerDomain bool

	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netaddr.IP
	// Domains are the search domains to use.
	Domains []string
}

// EquivalentTo determines whether its argument and receiver
// represent equivalent DNS configurations (then DNS reconfig is a no-op).
func (lhs Config) EquivalentTo(rhs Config) bool {
	if lhs.Disabled != rhs.Disabled || lhs.PerDomain != rhs.PerDomain {
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
	Logf logger.Logf

	// InterfaceName is the name of the interface whose DNS settings should be managed.
	InterfaceName string

	// Cleanup indicates that this manager is created for cleanup only.
	// A no-op manager will be instantiated if no cleanup is needed.
	Cleanup bool
	// PerDomain indicates that a manager capable of per-domain configuration is preferred.
	// Certain managers are per-domain only; they will not be considered if this is false.
	PerDomain bool
}
