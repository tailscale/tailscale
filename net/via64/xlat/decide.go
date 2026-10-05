// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package xlat manages kernel 4via6 translation on Linux subnet routers: nftables DNATs every advertised via prefix into one canonical prefix and NAT66s clients to one address, BPF programs on a netkit pair translate between IPv6 and IPv4 (RFC 7915), and NAT44 masquerades onto the LAN.
package xlat

import (
	"fmt"
	"net/netip"
	"slices"

	"go4.org/netipx"
	"tailscale.com/net/netutil"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/preftype"
)

// Canonical is the /96 every via prefix is DNATed into, whatever its site: grants are applied per site before the kernel sees the packet, and conntrack restores the site on replies. Its site ID is above what ValidateViaPrefix allows, so no node can advertise it, and bits 64-71 are zero as RFC 6052 requires.
var Canonical = netip.MustParsePrefix("fd7a:115c:a1e0:b1a:ff:ffff::/96")

// Xlat holds X4, the router-local IPv4 address that stands for every client.
type Xlat struct {
	X4 netip.Addr
}

// X6 returns X4 inside Canonical, the address NAT66 maps every client to.
func (x Xlat) X6() netip.Addr {
	a := Canonical.Addr().As16()
	b := x.X4.As4()
	copy(a[12:], b[:])
	return netip.AddrFrom16(a)
}

// Desired is the router's configuration, plus the host state the Controller reads.
type Desired struct {
	Advertised   []netip.Prefix // this node's advertised routes; non-via routes are ignored
	SNAT         bool
	Netfilter    preftype.NetfilterMode // only on: in nodivert mode Tailscale's FORWARD accepts are not called
	TunIPv6      bool                   // the router has IPv6 routes and filtering on the tun (it may not, see #20447)
	ForwardingV4 bool
	ForwardingV6 bool
	Firewalld    bool
	ForwardDrop  string // a forward chain with a drop policy that Tailscale's accepts do not reach
}

// noViaRoutes is decide's reason when there is nothing to translate; it is not logged.
const noViaRoutes = "no 4via6 routes are advertised"

// decide returns the advertised via prefixes the kernel should translate, or none and why not.
func decide(d Desired, x Xlat) (prefixes []netip.Prefix, why string) {
	for _, p := range d.Advertised {
		if tsaddr.IsViaPrefix(p) && netutil.ValidateViaPrefix(p) == nil {
			prefixes = append(prefixes, p.Masked())
		}
	}
	if len(prefixes) == 0 {
		return nil, noViaRoutes
	}
	switch {
	case d.Netfilter != preftype.NetfilterOn:
		return nil, "netfilter mode is " + d.Netfilter.String()
	case !d.SNAT:
		return nil, "SNAT for subnet routes is off"
	case !d.TunIPv6:
		return nil, "IPv6 is not usable on the Tailscale interface"
	case !d.ForwardingV4:
		return nil, "net.ipv4.ip_forward is not 1"
	case !d.ForwardingV6:
		return nil, "net.ipv6.conf.all.forwarding is not 1"
	case d.Firewalld:
		// firewalld's zones know nothing of the pair and would drop the forwarded traffic; not yet verified.
		return nil, "firewalld is running (not yet supported)"
	case d.ForwardDrop != "":
		return nil, "nftables chain " + d.ForwardDrop + " drops forwarded traffic, out of reach of Tailscale's rules"
	case !x.X4.Is4() || x.X4.IsUnspecified():
		return nil, fmt.Sprintf("X4 %v is not a usable IPv4 address", x.X4)
	}
	slices.SortFunc(prefixes, netipx.ComparePrefix)
	return slices.Compact(prefixes), ""
}
