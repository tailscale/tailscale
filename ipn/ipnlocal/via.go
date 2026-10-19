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
	"tailscale.com/net/routelimits"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
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

var envViaTargetAdditions = sync.OnceValue(func() *netipx.IPSet {
	v, err := generateEnvViaTargetAdditions(envknob.String(viaAdditionsEnv))
	if err != nil {
		log.Print(err)
	}

	if v != nil {
		has4via6AdditionsMetric := clientmetric.NewGauge("4via6_allow_local")
		has4via6AdditionsMetric.Set(1)
	}

	return v
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

// viaTargetDefaultAllowed reports whether ip may be forwarded to after
// unmapping a 4via6 destination. The packet filter only sees the outer via
// address, so this is a substitute for the normal destination IP filter in
// [tailscale.com/wgengine/filter] when via addresses are in use. Exceptions to
// the restrictions are handled before this func is called.
func viaTargetDefaultAllowed(ip netip.Addr) bool {
	if !ip.Is4() {
		return false // UnmapVia only returns IPv4
	}
	if additions := viaTargetAdditions(); additions != nil {
		// Permit unusual configurations to use host-scoped IP addresses as
		// 4via6 destinations when provided in an envknob.
		if additions.Contains(ip) {
			return true
		}
	}
	return !routelimits.IsDisallowed(ip)
}

var (
	v4Loopback  = netip.PrefixFrom(netip.AddrFrom4([4]byte{127, 0, 0, 0}), 8)
	v4LinkLocal = netip.PrefixFrom(netip.AddrFrom4([4]byte{169, 254, 0, 1}), 16)
)

func generateViaTargetAllowed(advertisedViaRoutes views.Slice[netip.Prefix]) func(netip.Addr) bool {
	var sb netipx.IPSetBuilder

	sb.AddSet(envViaTargetAdditions())

	// Loopback and link-local addresses that are normally restricted by
	// [routelimits.IsDisallowed] are permitted if there is a specific enough
	// route. Specific enough means that the prefix is fully contained within
	// the restricted range.
	for _, pfx := range advertisedViaRoutes.All() {
		if !tsaddr.IsViaPrefix(pfx) {
			continue
		}
		if pfx.Bits() < 96 {
			// The prefix is definitely too broad to allow
			continue
		}

		unmapped := netip.PrefixFrom(tsaddr.UnmapVia(pfx.Addr()), pfx.Bits()-96)

	}
}
