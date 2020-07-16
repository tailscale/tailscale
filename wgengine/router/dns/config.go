// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"inet.af/netaddr"
)

// Config is the subset of router.Config that contains DNS parameters.
type DNSConfig struct {
	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netaddr.IP
	// Domains are the search domains to use.
	Domains []string
	// PerDomain indicates whether it is preferred to use Nameservers
	// only for queries for subdomains of Domains.
	//
	// Note that Nameservers may still be applied to all queries
	// if the selected configuration mode does not support per-domain settings.
	PerDomain bool
}

// EquivalentTo determines whether its argument and receiver
// represent equivalent DNS configurations (then DNS reconfig is a no-op).
func (lhs Config) EquivalentTo(rhs Config) bool {
	if len(lhs.Nameservers) != len(rhs.Nameservers) {
		return false
	}

	if len(lhs.Domains) != len(rhs.Domains) {
		return false
	}

	if lhs.PerDomain != rhs.PerDomain {
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

// dnsMode determines how DNS settings are managed.
type dnsMode uint8

const (
	// dnsDirect indicates that /etc/resolv.conf is edited directly.
	dnsDirect dnsMode = iota
	// dnsResolvconf indicates that a resolvconf binary is used.
	dnsResolvconf
	// dnsNetworkManager indicates that the NetworkManaer DBus API is used.
	dnsNetworkManager
	// dnsResolved indicates that the systemd-resolved DBus API is used.
	dnsResolved
)

func (m dnsMode) String() string {
	switch m {
	case dnsDirect:
		return "direct"
	case dnsResolvconf:
		return "resolvconf"
	case dnsNetworkManager:
		return "networkmanager"
	case dnsResolved:
		return "resolved"
	default:
		return "???"
	}
}
