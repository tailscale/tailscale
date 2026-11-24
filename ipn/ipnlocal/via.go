// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"

	"go4.org/netipx"
	"tailscale.com/envknob"
	"tailscale.com/net/ipset"
	"tailscale.com/net/routelimits"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
)

// viaAdditionsEnv is the name of an environment variable that can be set to
// override the 4via6 host-scoped address restrictions. Only use this if you are
// certain that there is not a better solution (e.g. perhaps tailscale serve,
// possibly using a Service). Use of this feature will have security
// implications: ensure that your ACLs/Grants are written appropriately.
// The value of the environment variable is a comma separated list of IPv4
// ranges (two IPv4 addresses separated by a hyphen), IPv4 prefixes (CIDR
// notation), or IPv4 addresses. Spaces are permitted around the commas.
const viaAdditionsEnv = "TS_4VIA6_ALLOW_LOCAL"

var envViaTargetAdditions = sync.OnceValue(func() func(netip.Addr) bool {
	v, err := generateEnvViaTargetAdditions(envknob.String(viaAdditionsEnv))
	if err != nil {
		log.Printf("building envViaTargetAdditions: %v", err)
		return ipset.FalseContainsIPFunc()
	}

	if v == nil {
		return ipset.FalseContainsIPFunc()
	}

	has4via6AdditionsMetric := clientmetric.NewGauge("4via6_allow_local")
	has4via6AdditionsMetric.Set(1)
	return ipset.NewContainsIPFunc(views.SliceOf(v.Prefixes()))
})

func generateEnvViaTargetAdditions(rawAdditions string) (*netipx.IPSet, error) {
	rawAdditions = strings.TrimSpace(rawAdditions)
	if rawAdditions == "" {
		return nil, nil
	}

	var ips netipx.IPSetBuilder

	rawAddrs := strings.Split(rawAdditions, ",")
	errs := make([]error, 0, len(rawAddrs))
	for _, rawAddr := range rawAddrs {
		rawAddr = strings.TrimSpace(rawAddr)
		if rawAddr == "" {
			continue
		}

		// Try parsing as a range
		if ipRange, err := netipx.ParseIPRange(rawAddr); err == nil {
			if !ipRange.From().Is4() || !ipRange.To().Is4() {
				errs = append(errs, fmt.Errorf("rejecting %v range %v: not IPv4", viaAdditionsEnv, ipRange))
				continue
			}

			ips.AddRange(ipRange)
			continue
		}

		// Try parsing as a prefix
		if prefix, err := netip.ParsePrefix(rawAddr); err == nil {
			if !prefix.Addr().Is4() {
				errs = append(errs, fmt.Errorf("rejecting %v prefix %v: not IPv4", viaAdditionsEnv, prefix))
				continue
			}

			ips.AddPrefix(prefix)
			continue
		}

		// Try parsing as an individual IP
		if addr, err := netip.ParseAddr(rawAddr); err == nil {
			if !addr.Is4() {
				errs = append(errs, fmt.Errorf("rejecting %v address %v: not IPv4", viaAdditionsEnv, addr))
				continue
			}

			ips.Add(addr)
			continue
		}

		errs = append(errs, fmt.Errorf("rejecting %v value %q: not a range, prefix, or address", viaAdditionsEnv, rawAddr))
	}

	ipSet, err := ips.IPSet()
	if err != nil {
		errs = append(errs, err)
	}

	return ipSet, errors.Join(errs...)
}

// viaUnmappedTargetAllowed reports whether ip may be forwarded to after
// unmapping a 4via6 destination. The packet filter only sees the outer via
// address, so this is the sole check on the embedded IPv4 target.
func viaUnmappedTargetAllowed(ip netip.Addr) bool {
	if !ip.Is4() {
		return false // UnmapVia only returns IPv4
	}
	if envViaTargetAdditions()(ip) {
		// Permit unusual configurations to use host-scoped IP addresses as
		// 4via6 destinations when provided in an envknob.
		return true
	}
	return !routelimits.IsDisallowed(ip)
}

// viaPerSiteIDPrefixLength is the IPv6 prefix length for the entire IPv4
// address space within each site ID. It's 128 (v6 address length) - 32 (v4
// address length) = 96
const viaPerSiteIDPrefixLength = 96

// minViaExceptionPrefixLength is the shortest IPv6 prefix length for a 4via6
// route in viaHostLocalAdvertisablePrefixes.
const minViaExceptionPrefixLength = viaPerSiteIDPrefixLength + 8

// viaHostLocalAdvertisablePrefixes is the list of host-scoped prefixes that can
// be advertised via a subnet router but only when the advertisement is specific
// enough to ensure that advertising within host-scoped address space is
// intentional.
var viaHostLocalAdvertisablePrefixes = []netip.Prefix{
	netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 0}), 8),    // loopback
	netip.PrefixFrom(netip.AddrFrom4([4]byte{169, 254, 0, 0}), 16), // link-local
}

// generateViaAdvertisedAllowlist creates a func that returns true when a
// destination IP is a 4via6 address (still in 4via6 form) that should be
// permitted because the administrator has advertised a route indicating
// a deliberate choice to share potentially-sensitive destinations. The mapped
// address is used for this check so that only the site ID of the matching
// advertisement is permitted, rather than any site ID.
func generateViaAdvertisedAllowlist(advertisedRoutes views.Slice[netip.Prefix]) func(netip.Addr) bool {
	var restrictedBuilder netipx.IPSetBuilder
	for _, prefix := range viaHostLocalAdvertisablePrefixes {
		restrictedBuilder.AddPrefix(prefix)
	}
	for _, prefix := range routelimits.CloudMetadataPrefixes().All() {
		restrictedBuilder.AddPrefix(prefix)
	}

	var sb netipx.IPSetBuilder
	// Possible optimization: intersect with advertisedRoutes if that makes
	// envAdditions shorter.

	// Loopback and link-local addresses that are normally restricted by
	// [routelimits.IsDisallowed] are permitted if there is a specific enough
	// route. Specific enough means that the prefix is fully contained within
	// the restricted range.
	for _, pfx := range advertisedRoutes.All() {
		if pfx.Bits() < minViaExceptionPrefixLength {
			// The prefix is definitely too broad to allow: each 4via6 ID is a
			// /96 covering the entire IPv4 address space. Exceptions to the
			// restrictions requires at least /104 for loopback (127.0.0.0/8) or
			// /112 for link-local (169.254.0.0/16).
			// This also implicitly excludes all IPv4 routes.
			continue
		}
		mappedPrefix := pfx.Masked()
		if !tsaddr.IsViaPrefix(mappedPrefix) {
			continue
		}

		siteID, unmappedAddr := tsaddr.UnmapViaWithSiteID(mappedPrefix.Addr())
		if mappedPrefix.IsSingleIP() && routelimits.IsCloudMetadata()(unmappedAddr) {
			sb.AddPrefix(mappedPrefix)
			continue
		}

		for _, advertisable := range viaHostLocalAdvertisablePrefixes {
			if mappedPrefix.Bits() < viaPerSiteIDPrefixLength+advertisable.Bits() {
				continue
			}
			if !advertisable.Contains(unmappedAddr) {
				continue
			}

			// As an additional safety measure for addresses in
			// routelimits.isCloudMetadata, they require an exact match to be allowed.
			sb.AddPrefix(mappedPrefix)
			break
		}

		for _, addr := range viaHostLocalAdvertisableAddrs {
		}
	}

	for _, pfx := range advertisedRoutes.All() {
	}

	s, err := sb.IPSet()
	if err != nil {
		log.Printf("[unexpected] building viaTargetAllowed: %v", err)
		return ipset.FalseContainsIPFunc()
	}

	return ipset.NewContainsIPFunc(views.SliceOf(s.Prefixes()))
}
