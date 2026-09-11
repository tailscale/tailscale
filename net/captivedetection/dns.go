// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"sync"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// numWildcardProbes is how many nonexistent names the wildcard probe looks up.
// More than one, because a single answer could be a stale cache entry or a
// coincidence; a resolver that answers every name will answer all of them
// identically.
const numWildcardProbes = 2

// probeDNS looks for a hijacked resolver, which is how a captive portal gets a
// browser to its login page and is the most reliable evidence available when
// the network blackholes our HTTP probes outright.
//
// Both checks require the hijacked answer to be a local address. A resolver
// that returns some other public address for a name is doing something we can't
// distinguish from legitimate CDN or geo-DNS behavior, and acting on it would
// mean warning users about portals that don't exist.
//
// The queries go to the physical network's own resolvers; see
// [Detector.lookupIP]. They are not bound to a particular interface, because by
// the time we escalate this far no interface has reached anything and picking
// one to blame would be guesswork. On a machine with several active networks
// that means the answering resolver may not belong to the network we're
// investigating.
func (d *Detector) probeDNS(ctx context.Context, derpMap *tailcfg.DERPMap) []Signal {
	logf := d.logf

	var (
		mu      sync.Mutex
		signals []Signal
	)
	add := func(s Signal) {
		mu.Lock()
		defer mu.Unlock()
		signals = append(signals, s)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if d.probeDNSHijack(ctx, derpMap, logf) {
			add(SignalDNSHijack)
		}
	}()
	go func() {
		defer wg.Done()
		if d.probeDNSWildcard(ctx, logf) {
			add(SignalDNSWildcard)
		}
	}()
	wg.Wait()

	return signals
}

// probeDNSHijack reports whether a Tailscale hostname resolves to an address on
// the local network instead of its real one. We know the real addresses from the
// DERP map, so this needs no trusted third party.
func (d *Detector) probeDNSHijack(ctx context.Context, derpMap *tailcfg.DERPMap, logf logger.Logf) bool {
	host, want := derpNodeWithKnownAddr(derpMap)
	if host == "" {
		return false
	}

	got, err := d.lookupIP(ctx, host, 0)
	if err != nil || len(got) == 0 {
		logf("[v1] captivedetection: DNS hijack probe: lookup of %q failed: %v", host, err)
		return false
	}

	// If the resolver gave us any of the addresses we expected, it isn't
	// lying to us.
	for _, a := range got {
		if slices.Contains(want, a.Unmap()) {
			return false
		}
	}
	// The answer disagrees with the DERP map. Only a local address tells us a
	// portal is answering; anything else is more likely a DNS-based traffic
	// steering scheme we shouldn't second-guess.
	for _, a := range got {
		if isLocalAddr(a) {
			logf("captivedetection: %q resolved to local address %v, want one of %v; DNS is hijacked", host, a, want)
			return true
		}
	}
	logf("[v1] captivedetection: %q resolved to unexpected but non-local %v, want one of %v; inconclusive", host, got, want)
	return false
}

// probeDNSWildcard reports whether the resolver answers names that cannot
// exist with a local address, i.e. it resolves everything to the portal.
//
// The probe names are in the .invalid TLD, which RFC 6761 reserves and
// guarantees will never resolve, so a real answer can only have been
// fabricated.
func (d *Detector) probeDNSWildcard(ctx context.Context, logf logger.Logf) bool {
	var first netip.Addr
	for i := range numWildcardProbes {
		// The trailing dot makes this a fully-qualified name so the resolver
		// won't append search domains, which could otherwise turn it into a
		// name that legitimately resolves.
		name := "ts-portal-probe-" + strconv.Itoa(int(d.Now().UnixNano())+i) + ".invalid."
		got, err := d.lookupIP(ctx, name, 0)
		if err != nil || len(got) == 0 {
			// The expected outcome: NXDOMAIN.
			return false
		}
		a := got[0].Unmap()
		if !isLocalAddr(a) {
			// Some ISPs answer NXDOMAIN with a public search page. That's
			// obnoxious, but it isn't a captive portal.
			logf("[v1] captivedetection: %q resolved to non-local %v; not treating as a portal", name, a)
			return false
		}
		if i == 0 {
			first = a
			continue
		}
		if a != first {
			return false
		}
	}
	logf("captivedetection: resolver answers nonexistent .invalid names with local address %v; DNS is hijacked", first)
	return true
}

// derpNodeWithKnownAddr returns a DERP node hostname along with the IPv4
// addresses the DERP map says it has, for use as a DNS answer we can check
// against. It returns an empty host if the map has no usable node.
func derpNodeWithKnownAddr(derpMap *tailcfg.DERPMap) (host string, addrs []netip.Addr) {
	if derpMap == nil {
		return "", nil
	}
	// Iterate regions in a stable order so repeated probes are comparable, and
	// so tests don't depend on map iteration order.
	for _, rid := range slices.Sorted(maps.Keys(derpMap.Regions)) {
		region := derpMap.Regions[rid]
		if region == nil || region.Avoid || region.NoMeasureNoHome {
			continue
		}
		for _, node := range region.Nodes {
			if node.HostName == "" || node.IPv4 == "" {
				continue
			}
			ip, err := netip.ParseAddr(node.IPv4)
			if err != nil || !ip.Is4() {
				continue
			}
			return node.HostName, []netip.Addr{ip}
		}
	}
	return "", nil
}

// isLocalAddr reports whether ip is an address that can only belong to the
// local network or host: an RFC 1918 private address, a CGNAT address, a
// link-local address, or loopback. A DNS answer in this space for a name that
// lives on the public Internet means something on the LAN is answering.
func isLocalAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() ||
		tsaddr.CGNATRange().Contains(ip)
}
