// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package apitype

// DNSConfig is the DNS configuration for a tailnet
// used in /tailnet/{tailnet}/dns/config.
type DNSConfig struct {
	// Resolvers are the global DNS resolvers to use
	// overriding the local OS configuration.
	Resolvers []DNSResolver `json:"resolvers"`

	// FallbackResolvers are used as global resolvers when
	// the client is unable to determine the OS's preferred DNS servers.
	FallbackResolvers []DNSResolver `json:"fallbackResolvers"`

	// Routes map DNS name suffixes to a set of DNS resolvers,
	// used for Split DNS and other advanced routing overlays.
	Routes map[string][]DNSResolver `json:"routes"`

	// Domains are the search domains to use.
	Domains []string `json:"domains"`

	// Proxied means MagicDNS is enabled.
	Proxied bool `json:"proxied"`

	// TempCorpIssue13969 is from an internal hack day prototype,
	// See tailscale/corp#13969.
	TempCorpIssue13969 string `json:"TempCorpIssue13969,omitempty"`

	// Nameservers are the IP addresses of global nameservers to use.
	// This is a deprecated format but may still be found in tailnets
	// that were configured a long time ago. When making updates,
	// set Resolvers and leave Nameservers empty.
	Nameservers []string `json:"nameservers"`
}

// DNSResolver is a DNS resolver in a DNS configuration.
type DNSResolver struct {
	// Addr is the address of the DNS resolver.
	// It is usually an IP address or a DoH URL.
	// See dnstype.Resolver.Addr for full details.
	Addr string `json:"addr"`

	// BootstrapResolution is an optional suggested resolution for
	// the DoT/DoH resolver.
	BootstrapResolution []string `json:"bootstrapResolution,omitempty"`

	// UseWithExitNode signals this resolver should be used
	// even when a tailscale exit node is configured on a device.
	UseWithExitNode bool `json:"useWithExitNode,omitempty"`
}
