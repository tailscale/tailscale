// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"

	"tailscale.com/net/tsaddr"
)

// v4BroadcastAddr is 255.255.255.255, the limited broadcast address.
var v4BroadcastAddr = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// viaTargetAllowed reports whether ip may be forwarded to after unmapping a
// 4via6 destination. The packet filter only sees the outer via address, so
// this is the sole check on the embedded IPv4 target.
func viaTargetAllowed(ip netip.Addr) bool {
	if !ip.Is4() {
		return false // UnmapVia only returns IPv4
	} else if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip == v4BroadcastAddr {
		return false
	} else if tsaddr.IsTailscaleIP(ip) {
		// A CGNAT-range target may route to tailscale0 or to a site LAN
		// depending on the tailnet and OS (see shouldUseOneCGNATRoute);
		// it's hard to detect when forwarding would be OK, so deny always
		return false
	} else if ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}
