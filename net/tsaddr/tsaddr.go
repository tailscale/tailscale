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
	ula4To6Range oncePrefix
)

// TailscaleServiceIP returns the listen address of services
// provided by Tailscale itself such as the Magic DNS proxy.
func TailscaleServiceIP() netaddr.IP {
	serviceIP.Do(func() { mustIP(&serviceIP.v, "100.100.100.100") })
	return serviceIP.v
}

var serviceIP onceIP

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
	ulaRange.Do(func() { mustPrefix(&ulaRange.v, "fd7a:115c:a1e0::/48") })
	return ulaRange.v
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

// Tailscale4To6 returns a Tailscale IPv6 address that maps 1:1 to the
// given Tailscale IPv4 address. Returns a zero IP if ipv4 isn't a
// Tailscale IPv4 address.
func Tailscale4To6(ipv4 netaddr.IP) netaddr.IP {
	if !ipv4.Is4() || !IsTailscaleIP(ipv4) {
		return netaddr.IP{}
	}
	ret := Tailscale4To6Range().IP.As16()
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

func mustIP(v *netaddr.IP, ip string) {
	var err error
	*v, err = netaddr.ParseIP(ip)
	if err != nil {
		panic(err)
	}
}

type onceIP struct {
	sync.Once
	v netaddr.IP
}
