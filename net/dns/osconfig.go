// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "inet.af/netaddr"

// An OSConfigurator applies DNS settings to the operating system.
type OSConfigurator interface {
	// SetDNS updates the OS's DNS configuration to match cfg.
	// If cfg is the zero value, all Tailscale-related DNS
	// configuration is removed.
	// SetDNS must not be called after Close.
	SetDNS(cfg OSConfig) error
	// SupportsSplitDNS reports whether the configurator is capable of
	// installing a resolver only for specific DNS suffixes. If false,
	// the configurator can only set a global resolver.
	SupportsSplitDNS() bool
	// Close removes Tailscale-related DNS configuration from the OS.
	Close() error
}

// OSConfig is an OS DNS configuration.
type OSConfig struct {
	// Nameservers are the IP addresses of the nameservers to use.
	Nameservers []netaddr.IP
	// Domains are the search domains to use.
	Domains []string
	// Primary indicates whether to set Nameservers as the
	// primary/"default" resolvers for the system.
	// If false, Nameservers will be set as resolvers for Domains
	// only.
	// Primary=false is only allowed for OSConfigurators that report
	// SupportsSplitDNS.
	Primary bool
}
