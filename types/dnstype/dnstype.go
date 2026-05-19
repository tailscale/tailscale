// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package dnstype defines types for working with DNS.
package dnstype

//go:generate go run tailscale.com/cmd/viewer --type=Resolver --clonefunc=true

import (
	"net/netip"
	"net/url"
	"slices"
)

// Resolver is the configuration for one DNS resolver.
type Resolver struct {
	// Addr is the address of the DNS resolver, one of:
	//  - A plain IP address for a "classic" UDP+TCP DNS resolver.
	//    This is the common format as sent by the control plane.
	//  - An IP:port, for tests.
	//  - "https://resolver.com/path" for DNS over HTTPS; currently
	//    as of 2022-09-08 only used for certain well-known resolvers
	//    (see the publicdns package) for which the IP addresses to dial DoH are
	//    known ahead of time, so bootstrap DNS resolution is not required.
	//  - "http://node-address:port/path" for DNS over HTTP over WireGuard. This
	//    is implemented in the PeerAPI for exit nodes and app connectors.
	//  - [TODO] "tls://resolver.com" for DNS over TCP+TLS
	Addr string `json:",omitempty"`

	// BootstrapResolution is an optional suggested resolution for the
	// DoT/DoH resolver, if the resolver URL does not reference an IP
	// address directly.
	// BootstrapResolution may be empty, in which case clients should
	// look up the DoT/DoH server using their local "classic" DNS
	// resolver.
	//
	// As of 2022-09-08, BootstrapResolution is not yet used.
	BootstrapResolution []netip.Addr `json:",omitempty"`

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

// Hostname returns the host portion of r.Addr: the URL host for "https://"/"http://"/"tls://" forms, or the IP for any form accepted by [Resolver.IPPort]. Returns "" if r.Addr is empty or malformed. IPs from the IPPort path are canonicalized by [netip.Addr.String], so e.g. an embedded-IPv4 form like "[fd7a:115c:a1e0:b1a:0:1:1.2.3.4]:53" comes back rewritten as "fd7a:115c:a1e0:b1a:0:1:102:304" -- compare by re-parsing the result rather than string-matching against the original. URL-host IPs are returned verbatim from the URL.
func (r *Resolver) Hostname() string {
	if ipp, ok := r.IPPort(); ok {
		return ipp.Addr().String()
	}
	// IPPort returns ok=false for empty Addr and for URL forms (h/t prefix); url.Parse handles both safely (empty input parses to an empty URL with empty Hostname).
	if u, err := url.Parse(r.Addr); err == nil {
		return u.Hostname()
	}
	return ""
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
		slices.Equal(r.BootstrapResolution, other.BootstrapResolution) &&
		r.UseWithExitNode == other.UseWithExitNode
}
