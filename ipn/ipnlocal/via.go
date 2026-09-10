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
	"tailscale.com/net/tsaddr"
	"tailscale.com/util/clientmetric"
)

// v4BroadcastAddr is 255.255.255.255, the limited broadcast address.
var v4BroadcastAddr = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// viaAdditionsEnv is the name of an environment variable that can be set to
// override the 4via6 host-scoped address restrictions. Only use this if you are
// certain that there is not a better solution (e.g. perhaps tailscale serve,
// possibly using a Service). Use of this feature will have security
// implications: ensure that your ACLs/Grants are written appropriately.
// The value of the environment variable is a comma separated list of IPv4
// ranges (two IPv4 addresses separated by a hyphen), IPv4 prefixes (CIDR
// notation), or IPv4 addresses. Spaces are permitted around the commas.
const viaAdditionsEnv = "TS_4VIA6_ALLOW_LOCAL"

var viaTargetAdditions = sync.OnceValue(func() *netipx.IPSet {
	v, err := generateViaTargetAdditions(envknob.String(viaAdditionsEnv))
	if err != nil {
		log.Print(err)
	}

	if v != nil {
		has4via6AdditionsMetric := clientmetric.NewGauge("4via6_allow_local")
		has4via6AdditionsMetric.Set(1)
	}

	return v
})

func generateViaTargetAdditions(rawAdditions string) (*netipx.IPSet, error) {
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

// viaTargetAllowed reports whether ip may be forwarded to after unmapping a
// 4via6 destination. The packet filter only sees the outer via address, so
// this is the sole check on the embedded IPv4 target.
func viaTargetAllowed(ip netip.Addr) bool {
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
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip == v4BroadcastAddr {
		return false
	}
	if tsaddr.IsTailscaleIP(ip) {
		// A CGNAT-range target may route to tailscale0 or to a site LAN
		// depending on the tailnet and OS (see shouldUseOneCGNATRoute);
		// it's hard to detect when forwarding would be OK, so deny always
		return false
	}
	if ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}
