// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"fmt"
	"net/netip"
)

var vips = map[string]virtualIP{} // DNS name => details

var (
	fakeDNS               = newVIP("dns", "4.11.4.11", "2000:4:11::4:11")
	fakeProxyControlplane = newVIP("controlplane.tailscale.com", 1)
	fakeTestAgent         = newVIP("test-driver.tailscale", 2)
	fakeControl           = newVIP("control.tailscale", 3)
	fakeDERP1             = newVIP("derp1.tailscale", "33.4.0.1") // 3340=DERP; 1=derp 1
	fakeDERP2             = newVIP("derp2.tailscale", "33.4.0.2") // 3340=DERP; 2=derp 2
	fakeLogCatcher        = newVIP("log.tailscale.io", 4)
	fakeSyslog            = newVIP("syslog.tailscale", 9)
)

type virtualIP struct {
	name string // for DNS
	v4   netip.Addr
	v6   netip.Addr
}

func (v virtualIP) Match(a netip.Addr) bool {
	return v.v4 == a.Unmap() || v.v6 == a
}

// newVIP returns a new virtual IP.
//
// opts may be an IPv4 an IPv6 (in string form) or an int (bounded by uint8) to
// use IPv4 of 52.52.0.x.
//
// If the IPv6 is omitted, one is derived from the IPv4.
//
// If an opt is invalid or the DNS name is already used, it panics.
func newVIP(name string, opts ...any) (v virtualIP) {
	if _, ok := vips[name]; ok {
		panic(fmt.Sprintf("duplicate VIP %q", name))
	}
	v.name = name
	for _, o := range opts {
		switch o := o.(type) {
		case string:
			if ip, err := netip.ParseAddr(o); err == nil {
				if ip.Is4() {
					v.v4 = ip
				} else if ip.Is6() {
					v.v6 = ip
				}
			} else {
				panic(fmt.Sprintf("unsupported string option %q", o))
			}
		case int:
			if o <= 0 || o > 255 {
				panic(fmt.Sprintf("bad octet %d", o))
			}
			v.v4 = netip.AddrFrom4([4]byte{52, 52, 0, byte(o)})
		default:
			panic(fmt.Sprintf("unknown option type %T", o))
		}
	}
	if !v.v6.IsValid() && v.v4.IsValid() {
		// Map 1.2.3.4 to 2052::0102:0304
		a := [16]byte{0: 2, 2: 5, 3: 2} // 2052::
		copy(a[12:], v.v4.AsSlice())
		v.v6 = netip.AddrFrom16(a)
	}
	for _, b := range vips {
		if b.Match(v.v4) || b.Match(v.v6) {
			panic(fmt.Sprintf("VIP %q collides with %q", name, v.name))
		}
	}
	vips[name] = v
	return v
}
