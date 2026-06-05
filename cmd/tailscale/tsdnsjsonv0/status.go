// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsdnsjsonv0

// ExtraRecord is the JSON form of [tailscale.com/tailcfg.DNSRecord].
type ExtraRecord struct {
	Name  string
	Type  string `json:",omitempty"` // empty means A or AAAA, depending on Value
	Value string // typically an IP address
}

// ResolverInfo is the JSON form of [tailscale.com/types/dnstype.Resolver].
type ResolverInfo struct {
	// Addr is a plain IP, IP:port, DoH URL, or HTTP-over-WireGuard URL.
	Addr string

	// BootstrapResolution is optional pre-resolved IPs for DoT/DoH
	// resolvers whose address is not already an IP.
	BootstrapResolution []string `json:",omitempty"`
}

// SystemConfig is the OS DNS configuration as observed by Tailscale,
// mirroring [tailscale.com/net/dns.OSConfig].
type SystemConfig struct {
	Nameservers   []string `json:",omitzero"`
	SearchDomains []string `json:",omitzero"`

	// MatchDomains are DNS suffixes restricting which queries use
	// these Nameservers. Empty means Nameservers is the primary
	// resolver.
	MatchDomains []string `json:",omitzero"`
}

// TailnetInfo describes MagicDNS configuration for the tailnet,
// combining [tailscale.com/ipn/ipnstate.TailnetStatus]
// and [tailscale.com/ipn/ipnstate.PeerStatus].
type TailnetInfo struct {
	// MagicDNSEnabled is whether MagicDNS is enabled for the
	// tailnet. The device may still not use it if
	// --accept-dns=false.
	MagicDNSEnabled bool

	// MagicDNSSuffix is the tailnet's MagicDNS suffix
	// (e.g. "tail1234.ts.net"), without surrounding dots.
	MagicDNSSuffix string `json:",omitempty"`

	// SelfDNSName is this device's FQDN
	// (e.g. "host.tail1234.ts.net."), with trailing dot.
	SelfDNSName string `json:",omitempty"`
}

// StatusResponse is the full DNS status collected from the local
// Tailscale daemon. It is the output of:
//
//	$ tailscale dns status --json
type StatusResponse struct {
	// TailscaleDNS is whether the Tailscale DNS configuration is
	// installed on this device (the --accept-dns setting).
	TailscaleDNS bool

	// CurrentTailnet describes MagicDNS configuration for the tailnet.
	CurrentTailnet *TailnetInfo `json:",omitzero"` // nil if not connected

	// Resolvers are the DNS resolvers, in preference order. If
	// empty, the system defaults are used.
	Resolvers []ResolverInfo `json:",omitzero"`

	// SplitDNSRoutes maps domain suffixes to dedicated resolvers.
	// An empty resolver slice means the suffix is handled by
	// Tailscale's built-in resolver (100.100.100.100).
	SplitDNSRoutes map[string][]ResolverInfo `json:",omitzero"`

	// FallbackResolvers are like Resolvers but only used when
	// split DNS needs explicit default resolvers.
	FallbackResolvers []ResolverInfo `json:",omitzero"`

	SearchDomains []string `json:",omitzero"`

	// Nameservers are nameserver IPs.
	//
	// Deprecated: old protocol versions only. Use Resolvers.
	Nameservers []string `json:",omitzero"`

	// CertDomains are FQDNs for which the coordination server
	// provisions TLS certificates via dns-01 ACME challenges.
	CertDomains []string `json:",omitzero"`

	// ExtraRecords contains extra DNS records in the MagicDNS config.
	ExtraRecords []ExtraRecord `json:",omitzero"`

	// ExitNodeFilteredSet are DNS suffixes this node won't resolve
	// when acting as an exit node DNS proxy. Period-prefixed
	// entries are suffix matches; others are exact. Always
	// lowercase, no trailing dots.
	ExitNodeFilteredSet []string `json:",omitzero"`

	SystemDNS      *SystemConfig `json:",omitzero"` // nil if unavailable
	SystemDNSError string        `json:",omitempty"`
}
