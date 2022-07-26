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

// IPFrom16 returns the IP address given by the bytes in addr, unmapping any
// v6-mapped IPv4 address.
//
// It is equivalent to calling IPv6Raw(addr).Unmap().
func IPFrom16(a [16]byte) netip.Addr {
	return netip.AddrFrom16(a).Unmap()
}

// FromStdIP returns an IP from the standard library's IP type.
//
// If std is invalid, ok is false.
//
// FromStdIP implicitly unmaps IPv6-mapped IPv4 addresses. That is, if
// len(std) == 16 and contains an IPv4 address, only the IPv4 part is
// returned, without the IPv6 wrapper. This is the common form returned by
// the standard library's ParseIP: https://play.golang.org/p/qdjylUkKWxl.
// To convert a standard library IP without the implicit unmapping, use
// netip.AddrFromSlice.
func FromStdIP(std net.IP) (ip netip.Addr, ok bool) {
	ret, ok := netip.AddrFromSlice(std)
	if !ok {
		return ret, false
	}
	if ret.Is4In6() {
		return ret.Unmap(), true
	}
	return ret, true
}

// FromStdIPNet returns an IPPrefix from the standard library's IPNet type.
// If std is invalid, ok is false.
func FromStdIPNet(std *net.IPNet) (prefix netip.Prefix, ok bool) {
	ip, ok := FromStdIP(std.IP)
	if !ok {
		return netip.Prefix{}, false
	}

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
	ip, ok := FromStdIP(stdIP)
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
