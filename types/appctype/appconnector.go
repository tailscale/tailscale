// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package appcfg contains an experimental configuration structure for
// "tailscale.com/app-connectors" capmap extensions.
package appctype

import (
	"net/netip"
	"time"

	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
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

type Conn25Attr struct {
	// Name is the name of this collection of domains.
	Name string `json:"name,omitempty"`
	// Domains enumerates the domains serviced by the specified app connectors.
	// Domains can be of the form: example.com, or *.example.com.
	Domains []string `json:"domains,omitempty"`
	// Connectors enumerates the app connectors which service these domains.
	// These can either be "*" to match any advertising connector, or a
	// tag of the form tag:<tag-name>.
	Connectors []string `json:"connectors,omitempty"`
}

type Conn25PoolsAttr struct {
	V4MagicIPPool   []netipx.IPRange `json:"v4MagicIPPool,omitempty"`
	V4TransitIPPool []netipx.IPRange `json:"v4TransitIPPool,omitempty"`
	V6MagicIPPool   []netipx.IPRange `json:"v6MagicIPPool,omitempty"`
	V6TransitIPPool []netipx.IPRange `json:"v6TransitIPPool,omitempty"`
}

// Conn25ActiveState holds the active client and connector state.
type Conn25ActiveState struct {
	Configured bool                 `json:"configured"`
	Client     Conn25ClientState    `json:"client,omitzero"`
	Connector  Conn25ConnectorState `json:"connector,omitzero"`
}

// Conn25ClientState holds the active client state.
type Conn25ClientState struct {
	Apps        []Conn25ClientAppState  `json:"apps,omitempty"`
	IPPoolStats Conn25ClientIPPoolStats `json:"ipPoolStats,omitzero"`
}

// Conn25ClientIPPoolStats holds the in-use and total capacity counts for the
// client's magic and transit IP pools, split by address family. If a count
// exceeds [math.MaxInt64], that maximum is used instead.
type Conn25ClientIPPoolStats struct {
	IPv4MagicIPsInUse      int64 `json:"ipv4MagicIPsInUse"`
	IPv4MagicIPsCapacity   int64 `json:"ipv4MagicIPsCapacity"`
	IPv6MagicIPsInUse      int64 `json:"ipv6MagicIPsInUse"`
	IPv6MagicIPsCapacity   int64 `json:"ipv6MagicIPsCapacity"`
	IPv4TransitIPsInUse    int64 `json:"ipv4TransitIPsInUse"`
	IPv4TransitIPsCapacity int64 `json:"ipv4TransitIPsCapacity"`
	IPv6TransitIPsInUse    int64 `json:"ipv6TransitIPsInUse"`
	IPv6TransitIPsCapacity int64 `json:"ipv6TransitIPsCapacity"`
}

// Conn25ClientAppState holds the active client state for a single app,
// grouped by domain.
type Conn25ClientAppState struct {
	App     string                    `json:"app,omitempty"`
	Domains []Conn25ClientDomainState `json:"domains,omitempty"`
}

// Conn25ClientDomainState holds the address mappings the client has allocated
// for a single domain.
type Conn25ClientDomainState struct {
	Domain    dnsname.FQDN               `json:"domain"`
	Addresses []Conn25ClientAddressState `json:"addresses,omitempty"`
}

// Conn25ClientAddressState describes a single address mapping the client has
// allocated: the destination it resolves to, the magic and transit IPs handed
// out for it, its active flow count, and when the mapping expires.
type Conn25ClientAddressState struct {
	ActiveFlowCount int       `json:"activeFlowCount"`
	DestinationIP   string    `json:"destinationIP,omitempty"`
	MagicIP         string    `json:"magicIP,omitempty"`
	TransitIP       string    `json:"transitIP,omitempty"`
	ExpiresAt       time.Time `json:"expiresAt,omitzero"`
}

// Conn25ConnectorState holds the active connector state.
type Conn25ConnectorState struct {
	Peers []Conn25ConnectorPeerState `json:"peers,omitempty"`
}

// Conn25ConnectorPeerState holds the active connector state for a single peer
// (client) that has registered addresses with the connector, grouped by app.
type Conn25ConnectorPeerState struct {
	ClientIP string                    `json:"clientIP,omitempty"`
	Apps     []Conn25ConnectorAppState `json:"apps,omitempty"`
}

// Conn25ConnectorAppState holds the address mappings a peer has registered
// with the connector for a single app.
type Conn25ConnectorAppState struct {
	App       string                        `json:"app,omitempty"`
	Addresses []Conn25ConnectorAddressState `json:"addresses,omitempty"`
}

// Conn25ConnectorAddressState describes a single transit-to-destination IP
// mapping the connector routes on behalf of a peer.
type Conn25ConnectorAddressState struct {
	DestinationIP string `json:"destinationIP,omitempty"`
	TransitIP     string `json:"transitIP,omitempty"`
}
