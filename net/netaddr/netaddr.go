// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netaddr is a transitional package while we finish migrating from inet.af/netaddr
// to Go 1.18's net/netip.
//
// TODO(bradfitz): delete this package eventually. Tracking bug is
// https://github.com/tailscale/tailscale/issues/5162
package netaddr

import (
	"math"
	"net"
	"net/netip"
)

// IPv4 returns the IP of the IPv4 address a.b.c.d.
func IPv4(a, b, c, d uint8) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

// FromStdIPNet returns an IPPrefix from the standard library's IPNet type.
// If std is invalid, ok is false.
func FromStdIPNet(std *net.IPNet) (prefix netip.Prefix, ok bool) {
	ip, ok := netip.AddrFromSlice(std.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap()

	if l := len(std.Mask); l != net.IPv4len && l != net.IPv6len {
		// Invalid mask.
		return netip.Prefix{}, false
	}

	ones, bits := std.Mask.Size()
	if ones == 0 && bits == 0 {
		// IPPrefix does not support non-contiguous masks.
		return netip.Prefix{}, false
	}

	return netip.PrefixFrom(ip, ones), true
}

// FromStdAddr maps the components of a standard library TCPAddr or
// UDPAddr into an IPPort.
func FromStdAddr(stdIP net.IP, port int, zone string) (_ netip.AddrPort, ok bool) {
	ip, ok := netip.AddrFromSlice(stdIP)
	if !ok || port < 0 || port > math.MaxUint16 {
		return
	}
	ip = ip.Unmap()
	if zone != "" {
		if ip.Is4() {
			ok = false
			return
		}
		ip = ip.WithZone(zone)
	}
	return netip.AddrPortFrom(ip, uint16(port)), true
}
