// Copyright (c) Tailscale Inc & AUTHORS
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

	return r.Addr == other.Addr && slices.Equal(r.BootstrapResolution, other.BootstrapResolution)
}
