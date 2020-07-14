// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"time"

	"inet.af/netaddr"
)

// DNSConfig is the subset of Config that contains DNS parameters.
type DNSConfig struct {
	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netaddr.IP
	// Domains are the search domains to use.
	Domains []string
}

// EquivalentTo determines whether its argument and receiver
// represent equivalent DNS configurations (then DNS reconfig is a no-op).
func (lhs DNSConfig) EquivalentTo(rhs DNSConfig) bool {
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

	for i, domain := range lhs.Domains {
		if rhs.Domains[i] != domain {
			return false
		}
	}

	return true
}

// dnsReconfigTimeout is the timeout for DNS reconfiguration.
//
// This is useful because certain conditions can cause indefinite hangs
// (such as improper dbus auth followed by contextless dbus.Object.Call).
// Such operations should be wrapped in a timeout context.
const dnsReconfigTimeout = time.Second

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
