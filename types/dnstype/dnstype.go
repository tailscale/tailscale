// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnstype defines types for working with DNS.
package dnstype

//go:generate go run tailscale.com/cmd/cloner --type=Resolver --clonefunc=true --output=dnstype_clone.go

import "inet.af/netaddr"

// Resolver is the configuration for one DNS resolver.
type Resolver struct {
	// Addr is the address of the DNS resolver, one of:
	//  - A plain IP address for a "classic" UDP+TCP DNS resolver
	//  - [TODO] "tls://resolver.com" for DNS over TCP+TLS
	//  - [TODO] "https://resolver.com/query-tmpl" for DNS over HTTPS
	Addr string `json:",omitempty"`

	// BootstrapResolution is an optional suggested resolution for the
	// DoT/DoH resolver, if the resolver URL does not reference an IP
	// address directly.
	// BootstrapResolution may be empty, in which case clients should
	// look up the DoT/DoH server using their local "classic" DNS
	// resolver.
	BootstrapResolution []netaddr.IP `json:",omitempty"`
}

// ResolverFromIP defines a Resolver for ip on port 53.
func ResolverFromIP(ip netaddr.IP) Resolver {
	return Resolver{Addr: netaddr.IPPortFrom(ip, 53).String()}
}
