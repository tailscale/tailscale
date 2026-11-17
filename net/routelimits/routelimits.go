// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package routelimits performs tests to verify that mapped routing (4via6,
// conn25) operations do not allow communication that would normally be
// prevented by filters located elsewhere, such as
// [tailscale.com/wgengine/filter]. It also contains lists of
// potentially-sensitive cloud provider destinations.
package routelimits

import (
	"net/netip"
	"sync"

	"tailscale.com/net/ipset"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/views"
)

// v4BroadcastAddr is 255.255.255.255, the limited broadcast address.
var v4BroadcastAddr = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// isCloudMetadata returns true for IP addresses (v4 or v6) that are known to
// potentially contain cloud metadata. Most cloud providers document single
// addresses (/128) but sometimes they have multiple addresses, so all ULA IPv6
// addresses are recorded as their entire ULA prefix (/48).
var isCloudMetadata = sync.OnceValue(func() func(netip.Addr) bool {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("169.254.169.254/32"),  // standard IPv4 address
		netip.MustParsePrefix("fe80::a9fe:a9fe/128"), // commonly used link local IPv6 address

		// AWS
		// Standard IPv4 address
		netip.MustParsePrefix("fd00:ec2::/48"),

		// GCP
		// Standard IPv4 address
		netip.MustParsePrefix("fd20:ce::/48"),

		// Scaleway
		netip.MustParsePrefix("169.254.42.42/32"),
		netip.MustParsePrefix("fd00:42::/48"),

		// Akamai/Linode
		// Standard IPv4 address
		netip.MustParsePrefix("fd00:a9fe:a9fe::/48"),
		// Common link local IPv6 address

		// OCI (Oracle)
		// Standard IPv4 address
		netip.MustParsePrefix("fd00:c1::/48"),

		// Azure
		// Standard IPv4 address
		// Platform services at 168.63.129.16/32 is OK because it does not allow
		// IMDS access anymore and although it provides DNS access for a
		// filtered list of internal resources, reverse DNS is unsupported. It
		// can be excluded using other mechanisms if an administrator does not
		// want it exposed.
		// No IPv6 address

		// Hetzner
		// Standard IPv4 address
		// Common link local IPv6 address

		// Vultr, DigitalOcean
		// Standard IPv4 address
		// No IPv6 address

		// Alibaba
		netip.MustParsePrefix("100.100.100.200/32"),
	}

	return ipset.NewContainsIPFunc(views.SliceOf(prefixes))
})

// IsDisallowed reports whether addr is an IP address in an IP range
// that should not be allowed for various features that offer routing not
// protected by [tailscale.com/wgengine/filter.Filter] pre(): 4via6, conn25.
func IsDisallowed(addr netip.Addr) bool {
	if addr.IsLoopback() || addr.IsMulticast() || addr.IsUnspecified() ||
		addr == v4BroadcastAddr || addr.IsLinkLocalUnicast() || addr.Is4In6() {
		return true
	}
	if tsaddr.IsTailscaleIP(addr) {
		// A CGNAT-range target may route to tailscale0 or to a site LAN
		// depending on the tailnet and OS (see shouldUseOneCGNATRoute);
		// it's hard to detect when forwarding would be OK, so deny always
		return true
	}
	if isCloudMetadata()(addr) {
		return true
	}
	return false
}
