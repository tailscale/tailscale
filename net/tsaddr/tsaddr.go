// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tsaddr handles Tailscale-specific IPs and ranges.
package tsaddr

import (
	"sync"

	"inet.af/netaddr"
)

// ChromeOSVMRange returns the subset of the CGNAT IPv4 range used by
// ChromeOS to interconnect the host OS to containers and VMs. We
// avoid allocating Tailscale IPs from it, to avoid conflicts.
func ChromeOSVMRange() netaddr.IPPrefix {
	chromeOSRange.Do(func() { mustPrefix(&chromeOSRange.v, "100.115.92.0/23") })
	return chromeOSRange.v
}

var chromeOSRange oncePrefix

// CGNATRange returns the Carrier Grade NAT address range that
// is the superset range that Tailscale assigns out of.
// See https://tailscale.com/kb/1015/100.x-addresses.
// Note that Tailscale does not assign out of the ChromeOSVMRange.
func CGNATRange() netaddr.IPPrefix {
	cgnatRange.Do(func() { mustPrefix(&cgnatRange.v, "100.64.0.0/10") })
	return cgnatRange.v
}

var (
	cgnatRange   oncePrefix
	ulaRange     oncePrefix
	tsUlaRange   oncePrefix
	ula4To6Range oncePrefix
	ulaEph6Range oncePrefix
	serviceIPv6  oncePrefix
)

// TailscaleServiceIP returns the IPv4 listen address of services
// provided by Tailscale itself such as the MagicDNS proxy.
//
// For IPv6, use TailscaleServiceIPv6.
func TailscaleServiceIP() netaddr.IP {
	return netaddr.IPv4(100, 100, 100, 100) // "100.100.100.100" for those grepping
}

// TailscaleServiceIPv6 returns the IPv6 listen address of the services
// provided by Tailscale itself such as the MagicDNS proxy.
//
// For IPv4, use TailscaleServiceIP.
func TailscaleServiceIPv6() netaddr.IP {
	serviceIPv6.Do(func() { mustPrefix(&serviceIPv6.v, "fd7a:115c:a1e0::53/128") })
	return serviceIPv6.v.IP()
}

// IsTailscaleIP reports whether ip is an IP address in a range that
// Tailscale assigns from.
func IsTailscaleIP(ip netaddr.IP) bool {
	if ip.Is4() {
		return CGNATRange().Contains(ip) && !ChromeOSVMRange().Contains(ip)
	}
	return TailscaleULARange().Contains(ip)
}

// TailscaleULARange returns the IPv6 Unique Local Address range that
// is the superset range that Tailscale assigns out of.
func TailscaleULARange() netaddr.IPPrefix {
	tsUlaRange.Do(func() { mustPrefix(&tsUlaRange.v, "fd7a:115c:a1e0::/48") })
	return tsUlaRange.v
}

// Tailscale4To6Range returns the subset of TailscaleULARange used for
// auto-translated Tailscale ipv4 addresses.
func Tailscale4To6Range() netaddr.IPPrefix {
	// This IP range has no significance, beyond being a subset of
	// TailscaleULARange. The bits from /48 to /104 were picked at
	// random.
	ula4To6Range.Do(func() { mustPrefix(&ula4To6Range.v, "fd7a:115c:a1e0:ab12:4843:cd96:6200::/104") })
	return ula4To6Range.v
}

// TailscaleEphemeral6Range returns the subset of TailscaleULARange
// used for ephemeral IPv6-only Tailscale nodes.
func TailscaleEphemeral6Range() netaddr.IPPrefix {
	// This IP range has no significance, beyond being a subset of
	// TailscaleULARange. The bits from /48 to /64 were picked at
	// random, with the only criterion being to not be the conflict
	// with the Tailscale4To6Range above.
	ulaEph6Range.Do(func() { mustPrefix(&ulaEph6Range.v, "fd7a:115c:a1e0:efe3::/64") })
	return ulaEph6Range.v
}

// Tailscale4To6Placeholder returns an IP address that can be used as
// a source IP when one is required, but a netmap didn't provide
// any. This address never gets allocated by the 4-to-6 algorithm in
// control.
//
// Currently used to work around a Windows limitation when programming
// IPv6 routes in corner cases.
func Tailscale4To6Placeholder() netaddr.IP {
	return Tailscale4To6Range().IP()
}

// Tailscale4To6 returns a Tailscale IPv6 address that maps 1:1 to the
// given Tailscale IPv4 address. Returns a zero IP if ipv4 isn't a
// Tailscale IPv4 address.
func Tailscale4To6(ipv4 netaddr.IP) netaddr.IP {
	if !ipv4.Is4() || !IsTailscaleIP(ipv4) {
		return netaddr.IP{}
	}
	ret := Tailscale4To6Range().IP().As16()
	v4 := ipv4.As4()
	copy(ret[13:], v4[1:])
	return netaddr.IPFrom16(ret)
}

func mustPrefix(v *netaddr.IPPrefix, prefix string) {
	var err error
	*v, err = netaddr.ParseIPPrefix(prefix)
	if err != nil {
		panic(err)
	}
}

type oncePrefix struct {
	sync.Once
	v netaddr.IPPrefix
}

// NewContainsIPFunc returns a func that reports whether ip is in addrs.
//
// It's optimized for the cases of addrs being empty and addrs
// containing 1 or 2 single-IP prefixes (such as one IPv4 address and
// one IPv6 address).
//
// Otherwise the implementation is somewhat slow.
func NewContainsIPFunc(addrs []netaddr.IPPrefix) func(ip netaddr.IP) bool {
	// Specialize the three common cases: no address, just IPv4
	// (or just IPv6), and both IPv4 and IPv6.
	if len(addrs) == 0 {
		return func(netaddr.IP) bool { return false }
	}
	// If any addr is more than a single IP, then just do the slow
	// linear thing until
	// https://github.com/inetaf/netaddr/issues/139 is done.
	for _, a := range addrs {
		if a.IsSingleIP() {
			continue
		}
		acopy := append([]netaddr.IPPrefix(nil), addrs...)
		return func(ip netaddr.IP) bool {
			for _, a := range acopy {
				if a.Contains(ip) {
					return true
				}
			}
			return false
		}
	}
	// Fast paths for 1 and 2 IPs:
	if len(addrs) == 1 {
		a := addrs[0]
		return func(ip netaddr.IP) bool { return ip == a.IP() }
	}
	if len(addrs) == 2 {
		a, b := addrs[0], addrs[1]
		return func(ip netaddr.IP) bool { return ip == a.IP() || ip == b.IP() }
	}
	// General case:
	m := map[netaddr.IP]bool{}
	for _, a := range addrs {
		m[a.IP()] = true
	}
	return func(ip netaddr.IP) bool { return m[ip] }
}

// PrefixesContainsFunc reports whether f is true for any IPPrefix in
// ipp.
func PrefixesContainsFunc(ipp []netaddr.IPPrefix, f func(netaddr.IPPrefix) bool) bool {
	for _, v := range ipp {
		if f(v) {
			return true
		}
	}
	return false
}

// PrefixesContainsIP reports whether any prefix in ipp contains ip.
func PrefixesContainsIP(ipp []netaddr.IPPrefix, ip netaddr.IP) bool {
	for _, r := range ipp {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// IPsContainsFunc reports whether f is true for any IP in ips.
func IPsContainsFunc(ips []netaddr.IP, f func(netaddr.IP) bool) bool {
	for _, v := range ips {
		if f(v) {
			return true
		}
	}
	return false
}

// PrefixIs4 reports whether p is an IPv4 prefix.
func PrefixIs4(p netaddr.IPPrefix) bool { return p.IP().Is4() }

// PrefixIs6 reports whether p is an IPv6 prefix.
func PrefixIs6(p netaddr.IPPrefix) bool { return p.IP().Is6() }
