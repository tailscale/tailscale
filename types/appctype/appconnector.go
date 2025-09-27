// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package appcfg contains an experimental configuration structure for
// "tailscale.com/app-connectors" capmap extensions.
package appctype

import (
	"net/netip"

	"tailscale.com/tailcfg"
)

// ConfigID is an opaque identifier for a configuration.
type ConfigID string

// AppConnectorConfig is the configuration structure for an application
// connection proxy service.
type AppConnectorConfig struct {
	// DNAT is a map of destination NAT configurations.
	DNAT map[ConfigID]DNATConfig `json:",omitempty"`
	// SNIProxy is a map of SNI proxy configurations.
	SNIProxy map[ConfigID]SNIProxyConfig `json:",omitempty"`

	// AdvertiseRoutes indicates that the node should advertise routes for each
	// of the addresses in service configuration address lists. If false, the
	// routes have already been advertised.
	AdvertiseRoutes bool `json:",omitempty"`
}

// DNATConfig is the configuration structure for a destination NAT service, also
// known as a "port forward" or "port proxy".
type DNATConfig struct {
	// Addrs is a list of addresses to listen on.
	Addrs []netip.Addr `json:",omitempty"`

	// To is a list of destination addresses to forward traffic to. It should
	// only contain one domain, or a list of IP addresses.
	To []string `json:",omitempty"`

	// IP is a list of IP specifications to forward. If omitted, all protocols are
	// forwarded. IP specifications are of the form "tcp/80", "udp/53", etc.
	IP []tailcfg.ProtoPortRange `json:",omitempty"`
}

// SNIPRoxyConfig is the configuration structure for an SNI proxy service,
// forwarding TLS connections based on the hostname field in SNI.
type SNIProxyConfig struct {
	// Addrs is a list of addresses to listen on.
	Addrs []netip.Addr `json:",omitempty"`

	// IP is a list of IP specifications to forward. If omitted, all protocols are
	// forwarded. IP specifications are of the form "tcp/80", "udp/53", etc.
	IP []tailcfg.ProtoPortRange `json:",omitempty"`

	// AllowedDomains is a list of domains that are allowed to be proxied. If
	// the domain starts with a `.` that means any subdomain of the suffix.
	AllowedDomains []string `json:",omitempty"`
}

// AppConnectorAttr describes a set of domains
// serviced by specified app connectors.
type AppConnectorAttr struct {
	// Name is the name of this collection of domains.
	Name string `json:"name,omitempty"`
	// Domains enumerates the domains serviced by the specified app connectors.
	// Domains can be of the form: example.com, or *.example.com.
	Domains []string `json:"domains,omitempty"`
	// Routes enumerates the predetermined routes to be advertised by the specified app connectors.
	Routes []netip.Prefix `json:"routes,omitempty"`
	// Connectors enumerates the app connectors which service these domains.
	// These can either be "*" to match any advertising connector, or a
	// tag of the form tag:<tag-name>.
	Connectors []string `json:"connectors,omitempty"`
}

// RouteInfo is a data structure used to persist the in memory state of an AppConnector
// so that we can know, even after a restart, which routes came from ACLs and which were
// learned from domains.
type RouteInfo struct {
	// Control is the routes from the 'routes' section of an app connector acl.
	Control []netip.Prefix `json:",omitempty"`
	// Domains are the routes discovered by observing DNS lookups for configured domains.
	Domains map[string][]netip.Addr `json:",omitempty"`
	// Wildcards are the configured DNS lookup domains to observe. When a DNS query matches Wildcards,
	// its result is added to Domains.
	Wildcards []string `json:",omitempty"`
}

// RouteUpdate records a set of routes that should be advertised and a set of
// routes that should be unadvertised in event bus updates.
type RouteUpdate struct {
	Advertise   []netip.Prefix
	Unadvertise []netip.Prefix
}
