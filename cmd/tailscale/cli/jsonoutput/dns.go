// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonoutput

// DNSResolverInfo is the JSON form of [dnstype.Resolver].
type DNSResolverInfo struct {
	// Addr is a plain IP, IP:port, DoH URL, or HTTP-over-WireGuard URL.
	Addr string

	// BootstrapResolution is optional pre-resolved IPs for DoT/DoH
	// resolvers whose address is not already an IP.
	BootstrapResolution []string `json:",omitempty"`
}

// DNSExtraRecord is the JSON form of [tailcfg.DNSRecord].
type DNSExtraRecord struct {
	Name  string
	Type  string `json:",omitempty"` // empty means A or AAAA, depending on Value
	Value string // typically an IP address
}

// DNSSystemConfig is the OS DNS configuration as observed by Tailscale,
// mirroring [net/dns.OSConfig].
type DNSSystemConfig struct {
	Nameservers   []string `json:",omitzero"`
	SearchDomains []string `json:",omitzero"`

	// MatchDomains are DNS suffixes restricting which queries use
	// these Nameservers. Empty means Nameservers is the primary
	// resolver.
	MatchDomains []string `json:",omitzero"`
}

// DNSTailnetInfo describes MagicDNS configuration for the tailnet,
// combining [ipnstate.TailnetStatus] and [ipnstate.PeerStatus].
type DNSTailnetInfo struct {
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

// DNSStatusResult is the full DNS status collected from the local
// Tailscale daemon.
type DNSStatusResult struct {
	// TailscaleDNS is whether the Tailscale DNS configuration is
	// installed on this device (the --accept-dns setting).
	TailscaleDNS bool

	// CurrentTailnet describes MagicDNS configuration for the tailnet.
	CurrentTailnet *DNSTailnetInfo `json:",omitzero"` // nil if not connected

	// Resolvers are the DNS resolvers, in preference order. If
	// empty, the system defaults are used.
	Resolvers []DNSResolverInfo `json:",omitzero"`

	// SplitDNSRoutes maps domain suffixes to dedicated resolvers.
	// An empty resolver slice means the suffix is handled by
	// Tailscale's built-in resolver (100.100.100.100).
	SplitDNSRoutes map[string][]DNSResolverInfo `json:",omitzero"`

	// FallbackResolvers are like Resolvers but only used when
	// split DNS needs explicit default resolvers.
	FallbackResolvers []DNSResolverInfo `json:",omitzero"`

	SearchDomains []string `json:",omitzero"`

	// Nameservers are nameserver IPs.
	//
	// Deprecated: old protocol versions only. Use Resolvers.
	Nameservers []string `json:",omitzero"`

	// CertDomains are FQDNs for which the coordination server
	// provisions TLS certificates via dns-01 ACME challenges.
	CertDomains []string `json:",omitzero"`

	// ExtraRecords contains extra DNS records in the MagicDNS config.
	ExtraRecords []DNSExtraRecord `json:",omitzero"`

	// ExitNodeFilteredSet are DNS suffixes this node won't resolve
	// when acting as an exit node DNS proxy. Period-prefixed
	// entries are suffix matches; others are exact. Always
	// lowercase, no trailing dots.
	ExitNodeFilteredSet []string `json:",omitzero"`

	SystemDNS      *DNSSystemConfig `json:",omitzero"` // nil if unavailable
	SystemDNSError string           `json:",omitempty"`
}

// DNSAnswer is a single DNS resource record from a query response.
type DNSAnswer struct {
	Name  string
	TTL   uint32
	Class string // e.g. "ClassINET"
	Type  string // e.g. "TypeA", "TypeAAAA"
	Body  string // human-readable record data
}

// DNSQueryResult is the result of a DNS query via the Tailscale
// internal forwarder (100.100.100.100).
type DNSQueryResult struct {
	Name         string
	QueryType    string            // e.g. "A", "AAAA"
	Resolvers    []DNSResolverInfo `json:",omitzero"`
	ResponseCode string            // e.g. "RCodeSuccess", "RCodeNameError"
	Answers      []DNSAnswer       `json:",omitzero"`
}
