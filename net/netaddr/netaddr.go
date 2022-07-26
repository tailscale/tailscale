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

type (
	IP       = netip.Addr
	IPPort   = netip.AddrPort
	IPPrefix = netip.Prefix
)

// IPv4 returns the IP of the IPv4 address a.b.c.d.
func IPv4(a, b, c, d uint8) IP {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

// IPFrom16 returns the IP address given by the bytes in addr, unmapping any
// v6-mapped IPv4 address.
//
// It is equivalent to calling IPv6Raw(addr).Unmap().
func IPFrom16(a [16]byte) IP {
	return netip.AddrFrom16(a).Unmap()
}

// IPv6Raw returns the IPv6 address given by the bytes in addr, without an
// implicit Unmap call to unmap any v6-mapped IPv4 address.
func IPv6Raw(a [16]byte) IP {
	return netip.AddrFrom16(a) // no implicit unmapping
}

// IPFrom4 returns the IPv4 address given by the bytes in addr. It is equivalent
// to calling IPv4(addr[0], addr[1], addr[2], addr[3]).
func IPFrom4(a [4]byte) IP {
	return netip.AddrFrom4(a)
}

// IPPrefixFrom returns an IPPrefix with IP ip and provided bits prefix length.
// It does not allocate.
func IPPrefixFrom(ip IP, bits uint8) IPPrefix {
	return netip.PrefixFrom(ip, int(bits))
}

// IPPortFrom returns an IPPort with IP ip and port port. It does not allocate.
func IPPortFrom(ip IP, port uint16) IPPort {
	return netip.AddrPortFrom(ip, port)
}

// FromStdIPRaw returns an IP from the standard library's IP type.
// If std is invalid, ok is false.
// Unlike FromStdIP, FromStdIPRaw does not do an implicit Unmap if
// len(std) == 16 and contains an IPv6-mapped IPv4 address.
func FromStdIPRaw(std net.IP) (ip IP, ok bool) {
	return netip.AddrFromSlice(std)
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
// FromStdIPRaw.
func FromStdIP(std net.IP) (ip IP, ok bool) {
	ret, ok := FromStdIPRaw(std)
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
func FromStdIPNet(std *net.IPNet) (prefix IPPrefix, ok bool) {
	ip, ok := FromStdIP(std.IP)
	if !ok {
		return IPPrefix{}, false
	}

	if l := len(std.Mask); l != net.IPv4len && l != net.IPv6len {
		// Invalid mask.
		return IPPrefix{}, false
	}

	ones, bits := std.Mask.Size()
	if ones == 0 && bits == 0 {
		// IPPrefix does not support non-contiguous masks.
		return IPPrefix{}, false
	}

	return netip.PrefixFrom(ip, ones), true
}

// FromStdAddr maps the components of a standard library TCPAddr or
// UDPAddr into an IPPort.
func FromStdAddr(stdIP net.IP, port int, zone string) (_ IPPort, ok bool) {
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
