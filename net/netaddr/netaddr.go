// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netaddr is a transitional package while we finish migrating from inet.af/netaddr
// to Go 1.18's net/netip.
//
// TODO(bradfitz): delete this package eventually. Tracking bug is
// https://github.com/tailscale/tailscale/issues/5162
package netaddr

import (
	"net"
	"net/netip"
)

// IPv4 returns the IP of the IPv4 address a.b.c.d.
func IPv4(a, b, c, d uint8) netip.Addr {
	return netip.AddrFrom4([4]byte{a, b, c, d})
}

// Unmap returns the provided AddrPort with its Addr IP component Unmap'ed.
//
// See https://github.com/golang/go/issues/53607#issuecomment-1203466984
func Unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// FromStdIPNet returns an IPPrefix from the standard library's IPNet type.
// If std is invalid, ok is false.
func FromStdIPNet(std *net.IPNet) (prefix netip.Prefix, ok bool) {
	ip, ok := netip.AddrFromSlice(std.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ip = ip.Unmap()

	if ln := len(std.Mask); ln != net.IPv4len && ln != net.IPv6len {
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
