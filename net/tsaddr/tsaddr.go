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

var cgnatRange oncePrefix

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
	return CGNATRange().Contains(ip) && !ChromeOSVMRange().Contains(ip)
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
