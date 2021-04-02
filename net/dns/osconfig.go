// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

// DNSRoutingMode describes the type of per-domain DNS routing that
// the OS is capable of.
type RoutingMode int

const (
	// RoutingModeNone means the OS only supports setting a single
	// primary set of DNS resolvers.
	RoutingModeNone RoutingMode = iota
	// RoutingModeSingle means the OS supports a set of
	// primary resolvers, as well as one set of additional per-suffix
	// resolvers per network interface.
	RoutingModeSingle
	// RoutingModeMulti means the OS supports a set of primary
	// resolvers, as well as an arbitrary overlay of DNS routes.
	RoutingModeMulti
)

// An OSConfigurator applies DNS settings to the operating system.
type OSConfigurator interface {
	// Set updates the OS's DNS configuration to match cfg.
	// If cfg nil or the zero value, all Tailscale-related DNS
	// configuration is removed.
	// Set must not be called after Close.
	Set(cfg OSConfig) error
	// DNSRoutingMode reports the DNS routing capabilities of this OS
	// configurator.
	RoutingMode() RoutingMode
	// Close removes Tailscale-related DNS configuration from the OS.
	Close() error
}
