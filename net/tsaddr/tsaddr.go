// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tsaddr handles Tailscale-specific IPs and ranges.
package tsaddr

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"sync"

	"go4.org/netipx"
	"tailscale.com/net/netaddr"
	"tailscale.com/types/views"
)

// ChromeOSVMRange returns the subset of the CGNAT IPv4 range used by
// ChromeOS to interconnect the host OS to containers and VMs. We
// avoid allocating Tailscale IPs from it, to avoid conflicts.
func ChromeOSVMRange() netip.Prefix {
	chromeOSRange.Do(func() { mustPrefix(&chromeOSRange.v, "100.115.92.0/23") })
	return chromeOSRange.v
}

var chromeOSRange oncePrefix

// CGNATRange returns the Carrier Grade NAT address range that
// is the superset range that Tailscale assigns out of.
// See https://tailscale.com/s/cgnat
// Note that Tailscale does not assign out of the ChromeOSVMRange.
func CGNATRange() netip.Prefix {
	cgnatRange.Do(func() { mustPrefix(&cgnatRange.v, "100.64.0.0/10") })
	return cgnatRange.v
}

var (
	cgnatRange   oncePrefix
	tsUlaRange   oncePrefix
	tsViaRange   oncePrefix
	ula4To6Range oncePrefix
	ulaEph6Range oncePrefix
	serviceIPv6  oncePrefix
)

// TailscaleServiceIP returns the IPv4 listen address of services
// provided by Tailscale itself such as the MagicDNS proxy.
//
// For IPv6, use TailscaleServiceIPv6.
func TailscaleServiceIP() netip.Addr {
	return netaddr.IPv4(100, 100, 100, 100) // "100.100.100.100" for those grepping
}

// TailscaleServiceIPv6 returns the IPv6 listen address of the services
// provided by Tailscale itself such as the MagicDNS proxy.
//
// For IPv4, use TailscaleServiceIP.
func TailscaleServiceIPv6() netip.Addr {
	serviceIPv6.Do(func() { mustPrefix(&serviceIPv6.v, TailscaleServiceIPv6String+"/128") })
	return serviceIPv6.v.Addr()
}

const (
	TailscaleServiceIPString   = "100.100.100.100"
	TailscaleServiceIPv6String = "fd7a:115c:a1e0::53"
)

// IsTailscaleIP reports whether ip is an IP address in a range that
// Tailscale assigns from.
func IsTailscaleIP(ip netip.Addr) bool {
	if ip.Is4() {
		return CGNATRange().Contains(ip) && !ChromeOSVMRange().Contains(ip)
	}
	return TailscaleULARange().Contains(ip)
}

// TailscaleULARange returns the IPv6 Unique Local Address range that
// is the superset range that Tailscale assigns out of.
func TailscaleULARange() netip.Prefix {
	tsUlaRange.Do(func() { mustPrefix(&tsUlaRange.v, "fd7a:115c:a1e0::/48") })
	return tsUlaRange.v
}

// TailscaleViaRange returns the IPv6 Unique Local Address subset range
// TailscaleULARange that's used for IPv4 tunneling via IPv6.
func TailscaleViaRange() netip.Prefix {
	// Mnemonic: "b1a" sounds like "via".
	tsViaRange.Do(func() { mustPrefix(&tsViaRange.v, "fd7a:115c:a1e0:b1a::/64") })
	return tsViaRange.v
}

// Tailscale4To6Range returns the subset of TailscaleULARange used for
// auto-translated Tailscale ipv4 addresses.
func Tailscale4To6Range() netip.Prefix {
	// This IP range has no significance, beyond being a subset of
	// TailscaleULARange. The bits from /48 to /104 were picked at
	// random.
	ula4To6Range.Do(func() { mustPrefix(&ula4To6Range.v, "fd7a:115c:a1e0:ab12:4843:cd96:6200::/104") })
	return ula4To6Range.v
}

// TailscaleEphemeral6Range returns the subset of TailscaleULARange
// used for ephemeral IPv6-only Tailscale nodes.
func TailscaleEphemeral6Range() netip.Prefix {
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
func Tailscale4To6Placeholder() netip.Addr {
	return Tailscale4To6Range().Addr()
}

// Tailscale4To6 returns a Tailscale IPv6 address that maps 1:1 to the
// given Tailscale IPv4 address. Returns a zero IP if ipv4 isn't a
// Tailscale IPv4 address.
func Tailscale4To6(ipv4 netip.Addr) netip.Addr {
	if !ipv4.Is4() || !IsTailscaleIP(ipv4) {
		return netip.Addr{}
	}
	ret := Tailscale4To6Range().Addr().As16()
	v4 := ipv4.As4()
	copy(ret[13:], v4[1:])
	return netip.AddrFrom16(ret)
}

// Tailscale6to4 returns the IPv4 address corresponding to the given
// tailscale IPv6 address within the 4To6 range. The IPv4 address
// and true are returned if the given address was in the correct range,
// false if not.
func Tailscale6to4(ipv6 netip.Addr) (netip.Addr, bool) {
	if !ipv6.Is6() || !Tailscale4To6Range().Contains(ipv6) {
		return netip.Addr{}, false
	}
	v6 := ipv6.As16()
	return netip.AddrFrom4([4]byte{100, v6[13], v6[14], v6[15]}), true
}

func mustPrefix(v *netip.Prefix, prefix string) {
	var err error
	*v, err = netip.ParsePrefix(prefix)
	if err != nil {
		panic(err)
	}
}

type oncePrefix struct {
	sync.Once
	v netip.Prefix
}

// FalseContainsIPFunc is shorthand for NewContainsIPFunc(views.Slice[netip.Prefix]{}).
func FalseContainsIPFunc() func(ip netip.Addr) bool {
	return func(ip netip.Addr) bool { return false }
}

// NewContainsIPFunc returns a func that reports whether ip is in addrs.
//
// It's optimized for the cases of addrs being empty and addrs
// containing 1 or 2 single-IP prefixes (such as one IPv4 address and
// one IPv6 address).
//
// Otherwise the implementation is somewhat slow.
func NewContainsIPFunc(addrs views.Slice[netip.Prefix]) func(ip netip.Addr) bool {
	// Specialize the three common cases: no address, just IPv4
	// (or just IPv6), and both IPv4 and IPv6.
	if addrs.Len() == 0 {
		return func(netip.Addr) bool { return false }
	}
	// If any addr is more than a single IP, then just do the slow
	// linear thing until
	// https://github.com/inetaf/netaddr/issues/139 is done.
	if views.SliceContainsFunc(addrs, func(p netip.Prefix) bool { return !p.IsSingleIP() }) {
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
	// Fast paths for 1 and 2 IPs:
	if addrs.Len() == 1 {
		a := addrs.At(0)
		return func(ip netip.Addr) bool { return ip == a.Addr() }
	}
	if addrs.Len() == 2 {
		a, b := addrs.At(0), addrs.At(1)
		return func(ip netip.Addr) bool { return ip == a.Addr() || ip == b.Addr() }
	}
	// General case:
	m := map[netip.Addr]bool{}
	for i := range addrs.Len() {
		m[addrs.At(i).Addr()] = true
	}
	return func(ip netip.Addr) bool { return m[ip] }
}

// PrefixesContainsIP reports whether any prefix in ipp contains ip.
func PrefixesContainsIP(ipp []netip.Prefix, ip netip.Addr) bool {
	for _, r := range ipp {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// PrefixIs4 reports whether p is an IPv4 prefix.
func PrefixIs4(p netip.Prefix) bool { return p.Addr().Is4() }

// PrefixIs6 reports whether p is an IPv6 prefix.
func PrefixIs6(p netip.Prefix) bool { return p.Addr().Is6() }

// ContainsExitRoutes reports whether rr contains both the IPv4 and
// IPv6 /0 route.
func ContainsExitRoutes(rr views.Slice[netip.Prefix]) bool {
	var v4, v6 bool
	for i := range rr.Len() {
		r := rr.At(i)
		if r == allIPv4 {
			v4 = true
		} else if r == allIPv6 {
			v6 = true
		}
	}
	return v4 && v6
}

// ContainsNonExitSubnetRoutes reports whether v contains Subnet
// Routes other than ExitNode Routes.
func ContainsNonExitSubnetRoutes(rr views.Slice[netip.Prefix]) bool {
	for i := range rr.Len() {
		if rr.At(i).Bits() != 0 {
			return true
		}
	}
	return false
}

var (
	allIPv4 = netip.MustParsePrefix("0.0.0.0/0")
	allIPv6 = netip.MustParsePrefix("::/0")
)

// AllIPv4 returns 0.0.0.0/0.
func AllIPv4() netip.Prefix { return allIPv4 }

// AllIPv6 returns ::/0.
func AllIPv6() netip.Prefix { return allIPv6 }

// ExitRoutes returns a slice containing AllIPv4 and AllIPv6.
func ExitRoutes() []netip.Prefix { return []netip.Prefix{allIPv4, allIPv6} }

// SortPrefixes sorts the prefixes in place.
func SortPrefixes(p []netip.Prefix) {
	slices.SortFunc(p, netipx.ComparePrefix)
}

// FilterPrefixes returns a new slice, not aliasing in, containing elements of
// in that match f.
func FilterPrefixesCopy(in views.Slice[netip.Prefix], f func(netip.Prefix) bool) []netip.Prefix {
	var out []netip.Prefix
	for i := range in.Len() {
		if v := in.At(i); f(v) {
			out = append(out, v)
		}
	}
	return out
}

// IsViaPrefix reports whether p is a CIDR in the Tailscale "via" range.
// See TailscaleViaRange.
func IsViaPrefix(p netip.Prefix) bool {
	return TailscaleViaRange().Contains(p.Addr())
}

// UnmapVia returns the IPv4 address that corresponds to the provided Tailscale
// "via" IPv4-in-IPv6 address.
//
// If ip is not a via address, it returns ip unchanged.
func UnmapVia(ip netip.Addr) netip.Addr {
	if TailscaleViaRange().Contains(ip) {
		a := ip.As16()
		return netip.AddrFrom4(*(*[4]byte)(a[12:16]))
	}
	return ip
}

// MapVia returns an IPv6 "via" route for an IPv4 CIDR in a given siteID.
func MapVia(siteID uint32, v4 netip.Prefix) (via netip.Prefix, err error) {
	if !v4.Addr().Is4() {
		return via, errors.New("want IPv4 CIDR with a site ID")
	}
	viaRange16 := TailscaleViaRange().Addr().As16()
	var a [16]byte
	copy(a[:], viaRange16[:8])
	binary.BigEndian.PutUint32(a[8:], siteID)
	ip4a := v4.Addr().As4()
	copy(a[12:], ip4a[:])
	return netip.PrefixFrom(netip.AddrFrom16(a), v4.Bits()+64+32), nil
}
