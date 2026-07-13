// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package dnstype defines types for working with DNS.
package dnstype

//go:generate go run tailscale.com/cmd/viewer --type=Resolver --clonefunc=true

import (
	"net/netip"
	"slices"
)

// Resolver is the configuration for one DNS resolver.
type Resolver struct {
	// Addr is the address of the DNS resolver, one of:
	//  - A plain IP address for a "classic" UDP+TCP DNS resolver.
	//    This is the common format as sent by the control plane.
	//  - An IP:port, for tests.
	//  - "https://resolver.com/path" for DNS over HTTPS. The IPs to dial come
	//    from BootstrapResolution when that field is set, otherwise from the
	//    publicdns package when the URL is a well-known provider, otherwise
	//    resolved at dial time via in-memory MagicDNS or the system resolver.
	//    See BootstrapResolution for the nil-vs-empty distinction.
	//  - "http://node-address:port/path" for DNS over HTTP over WireGuard. This
	//    is implemented in the PeerAPI for exit nodes and app connectors.
	//  - [TODO] "tls://resolver.com" for DNS over TCP+TLS
	Addr string `json:",omitempty"`

	// BootstrapResolution lists IP addresses to use to reach the DoT/DoH
	// resolver, overriding any IPs that the client would otherwise infer
	// from Addr.
	//
	// The field carries three distinguishable states:
	//
	//   - nil (field absent): the client falls back to its own resolution.
	//     For DoH, that means the publicdns package when Addr is a
	//     well-known provider, else resolution at dial time.
	//   - non-empty: the listed IPs are used directly, taking precedence
	//     over publicdns and any dial-time resolution.
	//   - explicit empty list: the client uses dial-time resolution even
	//     if Addr would otherwise match a well-known provider.
	//
	// To preserve the nil-vs-empty distinction on the wire, this field is
	// intentionally not tagged `omitempty`.
	BootstrapResolution []netip.Addr

	// UseWithExitNode designates that this resolver should continue to be used when an
	// exit node is in use. Normally, DNS resolution is delegated to the exit node but
	// there are situations where it is preferable to still use a Split DNS server and/or
	// global DNS server instead of the exit node.
	UseWithExitNode bool `json:",omitempty"`
}

// IPPort returns r.Addr as an IP address and port if either
// r.Addr is an IP address (the common case) or if r.Addr
// is an IP:port (as done in tests).
func (r *Resolver) IPPort() (ipp netip.AddrPort, ok bool) {
	if r.Addr == "" || r.Addr[0] == 'h' || r.Addr[0] == 't' {
		// Fast path to avoid ParseIP error allocation for obviously not IP
		// cases.
		return
	}
	if ip, err := netip.ParseAddr(r.Addr); err == nil {
		return netip.AddrPortFrom(ip, 53), true
	}
	if ipp, err := netip.ParseAddrPort(r.Addr); err == nil {
		return ipp, true
	}
	return
}

// Equal reports whether r and other are equal.
func (r *Resolver) Equal(other *Resolver) bool {
	if r == nil || other == nil {
		return r == other
	}
	if r == other {
		return true
	}

	return r.Addr == other.Addr &&
		(r.BootstrapResolution == nil) == (other.BootstrapResolution == nil) &&
		slices.Equal(r.BootstrapResolution, other.BootstrapResolution) &&
		r.UseWithExitNode == other.UseWithExitNode
}
