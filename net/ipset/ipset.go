// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ipset provides code for creating efficient IP-in-set lookup functions
// with different implementations depending on the set.
package ipset

import (
	"net/netip"

	"github.com/gaissmai/bart"
	"tailscale.com/types/views"
)

// FalseContainsIPFunc is shorthand for NewContainsIPFunc(views.Slice[netip.Prefix]{}).
func FalseContainsIPFunc() func(ip netip.Addr) bool {
	return func(ip netip.Addr) bool { return false }
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
		return func(netip.Addr) bool { return false }
	}
	// If any addr is a prefix with more than a single IP, then do either a
	// linear scan or a bart table, depending on the number of addrs.
	if addrs.ContainsFunc(func(p netip.Prefix) bool { return !p.IsSingleIP() }) {
		if addrs.Len() > 6 {
			pathForTest("bart")
			// Built a bart table.
			t := &bart.Table[struct{}]{}
			for i := range addrs.Len() {
				t.Insert(addrs.At(i), struct{}{})
			}
			return func(ip netip.Addr) bool {
				_, ok := t.Get(ip)
				return ok
			}
		} else {
			pathForTest("linear-contains")
			// Small enough to do a linear search.
			acopy := addrs.AsSlice()
			return func(ip netip.Addr) bool {
				for _, a := range acopy {
					if a.Contains(ip) {
						return true
					}
				}
				return false
			}
		}
	}
	// Fast paths for 1 and 2 IPs:
	if addrs.Len() == 1 {
		pathForTest("one-ip")
		a := addrs.At(0)
		return func(ip netip.Addr) bool { return ip == a.Addr() }
	}
	if addrs.Len() == 2 {
		pathForTest("two-ip")
		a, b := addrs.At(0), addrs.At(1)
		return func(ip netip.Addr) bool { return ip == a.Addr() || ip == b.Addr() }
	}
	// General case:
	pathForTest("ip-map")
	m := map[netip.Addr]bool{}
	for i := range addrs.Len() {
		m[addrs.At(i).Addr()] = true
	}
	return func(ip netip.Addr) bool { return m[ip] }
}
