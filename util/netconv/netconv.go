// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netconv provides utilities to convert between netaddr and netip.
// To convert from a net.IP, use the netaddr/netip API.
package netconv

import (
	"net/netip"

	"inet.af/netaddr"
)

// AsIP returns a as a netaddr.IP.
func AsIP(a netip.Addr) netaddr.IP {
	switch {
	case a.Is4():
		return netaddr.IPFrom4(a.As4())
	case a.Is6():
		return netaddr.IPv6Raw(a.As16()).WithZone(a.Zone())
	}
	return netaddr.IP{}
}

// AsAddr returns a as a netip.IP.
func AsAddr(a netaddr.IP) netip.Addr {
	switch {
	case a.Is4():
		return netip.AddrFrom4(a.As4())
	case a.Is6():
		return netip.AddrFrom16(a.As16()).WithZone(a.Zone())
	}
	return netip.Addr{}
}

// AsIPPrefix returns a as a netaddr.IPPrefix.
// If a has Bits of -1, indicating an invalid bits,
// the returned IPPrefix will have Bits of 255.
// AsIPPrefix and AsPrefix do not
// round trip for invalid Bits values.
func AsIPPrefix(a netip.Prefix) netaddr.IPPrefix {
	return netaddr.IPPrefixFrom(AsIP(a.Addr()), uint8(a.Bits()))
}

// AsPrefix returns a as a netip.Prefix.
// If a has an invalid Bits value,
// the returned Prefix will have Bits of -1.
// AsIPPrefix and AsPrefix do not
// round trip for invalid Bits values.
func AsPrefix(a netaddr.IPPrefix) netip.Prefix {
	return netip.PrefixFrom(AsAddr(a.IP()), int(a.Bits()))
}

// AsIPPort returns a as a netaddr.IPPort.
func AsIPPort(a netip.AddrPort) netaddr.IPPort {
	return netaddr.IPPortFrom(AsIP(a.Addr()), a.Port())
}

// AsAddrPort returns a as a netip.AddrPort.
func AsAddrPort(a netaddr.IPPort) netip.AddrPort {
	return netip.AddrPortFrom(AsAddr(a.IP()), a.Port())
}
