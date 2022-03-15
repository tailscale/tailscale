// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package netconv

import (
	"net/netip"
	"testing"

	qt "github.com/frankban/quicktest"
	"inet.af/netaddr"
)

func TestAddr(t *testing.T) {
	c := qt.New(t)

	c.Assert(netip.Addr{}, qt.Equals, AsAddr(netaddr.IP{}))
	c.Assert(netaddr.IP{}, qt.Equals, AsIP(netip.Addr{}))

	// Cover IPv4, IPv6, 4in6, and zones.
	addrStrs := []string{
		"0.0.0.0",
		"123.45.67.89",
		"::",
		"fd7a:115c:a1e0:ab12:4843:cd96:626b:430b",
		"fd7a:115c:a1e0:ab12:4843:cd96:626b:430b%eth0",
		"::ffff:192.0.2.128",
		"::ffff:192.0.2.128%eth0",
	}
	for _, s := range addrStrs {
		ip := netaddr.MustParseIP(s)
		addr := netip.MustParseAddr(s)
		c.Assert(addr, qt.Equals, AsAddr(ip))
		c.Assert(ip, qt.Equals, AsIP(addr))
	}
}

func TestAddrPort(t *testing.T) {
	c := qt.New(t)

	c.Assert(netip.AddrPort{}, qt.Equals, AsAddrPort(netaddr.IPPort{}))
	c.Assert(netaddr.IPPort{}, qt.Equals, AsIPPort(netip.AddrPort{}))

	// Test just a single AddrPort conversion;
	// there's almost nothing happening in the code.
	portStr := "1.2.4.5:8"
	ipPort := netaddr.MustParseIPPort(portStr)
	ap := netip.MustParseAddrPort(portStr)
	c.Assert(ipPort, qt.Equals, AsIPPort(ap))
	c.Assert(ap, qt.Equals, AsAddrPort(ipPort))
}

func TestPrefix(t *testing.T) {
	c := qt.New(t)

	// The interesting Prefix cases are invalid bits.
	addr := netip.MustParseAddr("1.2.3.4")
	ip := AsIP(addr)

	tests := []struct {
		ipp netaddr.IPPrefix // input IPPrefix, output from converting pfx
		pfx netip.Prefix     // input Prefix, output from converting ipp
		out netaddr.IPPrefix // output from converting pfx
	}{
		{netaddr.IPPrefix{}, netip.Prefix{}, netaddr.IPPrefix{}},
		{netaddr.IPPrefixFrom(ip, 24), netip.PrefixFrom(addr, 24), netaddr.IPPrefixFrom(ip, 24)},
		{netaddr.IPPrefixFrom(ip, 255), netip.PrefixFrom(addr, -1), netaddr.IPPrefixFrom(ip, 255)},
		{netaddr.IPPrefixFrom(ip, 204), netip.PrefixFrom(addr, -1), netaddr.IPPrefixFrom(ip, 255)},
	}

	for _, test := range tests {
		c.Assert(test.out, qt.Equals, AsIPPrefix(test.pfx))
		c.Assert(test.pfx, qt.Equals, AsPrefix(test.ipp))
	}
}
