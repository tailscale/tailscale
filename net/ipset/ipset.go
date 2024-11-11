// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ipset provides code for creating efficient IP-in-set lookup functions
// with different implementations depending on the set.
package ipset

import (
	"net/netip"

	"github.com/gaissmai/bart"
	"tailscale.com/types/views"
	"tailscale.com/util/set"
)

// FalseContainsIPFunc is shorthand for NewContainsIPFunc(views.Slice[netip.Prefix]{}).
func FalseContainsIPFunc() func(ip netip.Addr) bool {
	return emptySet
}

func emptySet(ip netip.Addr) bool { return false }

func bartLookup(t *bart.Table[struct{}]) func(netip.Addr) bool {
	return func(ip netip.Addr) bool {
		_, ok := t.Lookup(ip)
		return ok
	}
}

func prefixContainsLoop(addrs []netip.Prefix) func(netip.Addr) bool {
	return func(ip netip.Addr) bool {
		for _, p := range addrs {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
}

func oneIP(ip1 netip.Addr) func(netip.Addr) bool {
	return func(ip netip.Addr) bool { return ip == ip1 }
}

func twoIP(ip1, ip2 netip.Addr) func(netip.Addr) bool {
	return func(ip netip.Addr) bool { return ip == ip1 || ip == ip2 }
}

func ipInMap(m set.Set[netip.Addr]) func(netip.Addr) bool {
	return func(ip netip.Addr) bool {
		_, ok := m[ip]
		return ok
	}
}

// pathForTest is a test hook for NewContainsIPFunc, to test that it took the
// right construction path.
var pathForTest = func(string) {}

// NewContainsIPFunc returns a func that reports whether ip is in addrs.
//
// The returned func is optimized for the length of contents of addrs.
func NewContainsIPFunc(addrs views.Slice[netip.Prefix]) func(ip netip.Addr) bool {
	// Specialize the three common cases: no address, just IPv4
	// (or just IPv6), and both IPv4 and IPv6.
	if addrs.Len() == 0 {
		pathForTest("empty")
		return emptySet
	}
	// If any addr is a prefix with more than a single IP, then do either a
	// linear scan or a bart table, depending on the number of addrs.
	if addrs.ContainsFunc(func(p netip.Prefix) bool { return !p.IsSingleIP() }) {
		if addrs.Len() == 1 {
			pathForTest("one-prefix")
			return addrs.At(0).Contains
		}
		if addrs.Len() <= 6 {
			// Small enough to do a linear search.
			pathForTest("linear-contains")
			return prefixContainsLoop(addrs.AsSlice())
		}
		pathForTest("bart")
		// Built a bart table.
		t := &bart.Table[struct{}]{}
		for _, p := range addrs.All() {
			t.Insert(p, struct{}{})
		}
		return bartLookup(t)
	}
	// Fast paths for 1 and 2 IPs:
	if addrs.Len() == 1 {
		pathForTest("one-ip")
		return oneIP(addrs.At(0).Addr())
	}
	if addrs.Len() == 2 {
		pathForTest("two-ip")
		return twoIP(addrs.At(0).Addr(), addrs.At(1).Addr())
	}
	// General case:
	pathForTest("ip-map")
	m := set.Set[netip.Addr]{}
	for _, p := range addrs.All() {
		m.Add(p.Addr())
	}
	return ipInMap(m)
}
