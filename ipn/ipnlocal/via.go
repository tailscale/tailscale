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
// be advertised by a 4via6 subnet router but only when the advertisement is
// specific enough to ensure that advertising within host-scoped address space
// is intentional.
var viaHostLocalAdvertisablePrefixes = sync.OnceValue(func() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),    // loopback
		netip.MustParsePrefix("169.254.0.0/16"), // link-local
		tsaddr.CGNATRange(),
	}
})

// generateViaAdvertisedAllowlist creates a func that returns true when a
// destination IP is a 4via6 address (still in 4via6 form) that should be
// permitted because the administrator has advertised a route indicating
// a deliberate choice to share potentially-sensitive destinations. The mapped
// address is used for this check so that only the site ID of the matching
// advertisement is permitted, rather than any site ID.
//
// The list is generated in 3 phases. The changes applied in each phase override
// any previous phases.
//  1. Add 4via6 destinations to host-scoped addresses when the advertisement
//     is sufficiently specific. Only the site ID(s) with qualifying
//     advertisements allow those destinations.
//  2. Remove cloud metadata prefixes from every site ID in use, even if allowed
//     by phase 1.
//  3. Add 4via6 destinations that are advertised as a single IP and fall into
//     the cloud metadata ranges. Like phase 1, the only site IDs allowed for
//     those destinations are those with qualifying advertisements. As of
//     2026-11-25, the only IPv4 cloud metadata prefixes are 3 single IPs, so
//     nobody should need to add an undue number of additional advertisements to
//     work around this restriction when desired.
func generateViaAdvertisedAllowlist(advertisedRoutes views.Slice[netip.Prefix]) *netipx.IPSet {
	if advertisedRoutes.Len() == 0 {
		return nil
	}
	// cloudMetadataIPs records the single IP advertisements that have been
	// observed so far.
	//
	// Cloud metadata endpoints are extra sensitive, so we require those to be
	// advertised explicitly (using a 4via6 /128) even when an advertisement is
	// less specific but still specific enough to normally grant an exception
	// For example, the 4via6 mapped equivalent to 169.254.169.0/24 will still
	// exclude 169.254.169.254.
	var cloudMetadataIPs []netip.Addr
	// siteIDs is the list of site IDs in use so that we can efficiently remove
	// cloud metadata prefixes from them.
	siteIDs := make(set.Set[uint32])
	var sb netipx.IPSetBuilder

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
			cloudMetadataIPs = append(cloudMetadataIPs, mappedPrefix.Addr())
			continue
		}

		for _, advertisable := range viaHostLocalAdvertisablePrefixes() {
			if mappedPrefix.Bits() < viaPerSiteIDPrefixLength+advertisable.Bits() {
				continue
			}
			if !advertisable.Contains(unmappedAddr) {
				continue
			}

			// As an additional safety measure for addresses in
			// routelimits.isCloudMetadata, they require an exact match to be allowed.
			sb.AddPrefix(mappedPrefix)
			siteIDs.Add(siteID)
			break
		}
	}

	if len(siteIDs) > 0 {
		for _, cloudMetaPrefix := range routelimits.CloudMetadataPrefixes().All() {
			if !cloudMetaPrefix.Addr().Is4() {
				continue
			}
			for siteID := range siteIDs {
				via, err := tsaddr.MapVia(siteID, cloudMetaPrefix)
				if err != nil {
					continue
				}
				sb.RemovePrefix(via)
			}
		}
	}

	for _, addr := range cloudMetadataIPs {
		sb.Add(addr)
	}

	s, err := sb.IPSet()
	if err != nil {
		log.Printf("[unexpected] building viaTargetAllowed: %v", err)
		return nil
	}

	if s.Equal(&netipx.IPSet{}) {
		return nil
	}

	return s
}
