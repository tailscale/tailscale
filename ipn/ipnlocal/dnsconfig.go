// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/gaissmai/bart"
	"tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/wgcfg"
)

// filterUnreachableSplitDNS removes from dcfg.Routes any resolver whose tailnet-space destination IPs aren't reachable.
//
// A destination IP is reachable if it's covered by a peer AllowedIPs entry in cfg, by nm.SelfNode.AllowedIPs (own addresses + approved subnet/app-connector routes; the local node handles those as loopback), or by an advertised 4via6 prefix in nm.SelfNode.Hostinfo.RoutableIPs (netstack handles those as loopback even before control approves the route, per #12016).
//
// If a suffix's entire resolver list is filtered out, the suffix is also deleted from dcfg.Routes. dcfg.DefaultResolvers (the "." suffix) is never filtered.
//
// AllowedIPs (not the flattened rcfg.Routes) is the source of peer reachability because [peerRoutes] collapses every tailnet IPv6 into one fd7a:115c:a1e0::/48 prefix — a routing-table optimisation that erases the per-destination granularity we need here.
//
// Returns a suffix -> filtered-resolvers map for diagnostic surfacing. Keys match the wire format used by [tailcfg.DNSConfig.Routes] (no trailing dot). Returns nil if nothing was filtered.
func filterUnreachableSplitDNS(dcfg *dns.Config, cfg *wgcfg.Config, nm *netmap.NetworkMap) (filtered map[string][]*dnstype.Resolver) {
	magicDNSSuffixLower := strings.ToLower(nm.MagicDNSSuffix())

	// routes is the union of every peer's AllowedIPs: the set of tailnet destinations currently reachable through wireguard.
	routes := &bart.Lite{}
	for _, p := range cfg.Peers {
		for _, pfx := range p.AllowedIPs {
			routes.Insert(pfx)
		}
	}
	// Self addresses and any approved subnet/app-connector routes are reachable as loopback; both live in nm.SelfNode.AllowedIPs. Additionally, 4via6 routes the node advertises function locally even before control approves them — netstack handles them as loopback (see #12016) — so add advertised RoutableIPs in the 4via6 range too.
	if nm.SelfNode.Valid() {
		for _, pfx := range nm.SelfNode.AllowedIPs().All() {
			routes.Insert(pfx)
		}
		if hi := nm.SelfNode.Hostinfo(); hi.Valid() {
			viaRange := tsaddr.TailscaleViaRange()
			for _, pfx := range hi.RoutableIPs().All() {
				if viaRange.Contains(pfx.Addr()) {
					routes.Insert(pfx)
				}
			}
		}
	}

	// isReachable reports whether ip is reachable: non-Tailscale (out of scope; we don't probe) or a tailnet IP with a covering peer route.
	isReachable := func(ip netip.Addr) bool {
		return !tsaddr.IsTailscaleIP(ip) || routes.Contains(ip)
	}

	// peerIPs is built lazily on the first resolver whose Addr is a URL hostname (vs. an IP form). A config that only uses IP-literal resolvers pays nothing for materialising the per-peer IP slices.
	var peerIPs map[string][]netip.Addr

	// shouldDrop reports whether to drop r: it has tailnet-intent IPs and none are reachable.
	shouldDrop := func(r *dnstype.Resolver) bool {
		if ips := r.BootstrapResolution; len(ips) > 0 {
			return !slices.ContainsFunc(ips, isReachable)
		}
		if ipp, ok := r.IPPort(); ok {
			return !isReachable(ipp.Addr())
		}
		host := strings.ToLower(r.Hostname())
		if host == "" {
			return false
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			// URL form with an IP literal as host, e.g. http://100.64.0.5/dns-query.
			return !isReachable(ip)
		}
		if peerIPs == nil {
			peerIPs = peerIPsFromNetmap(nm)
		}
		if found := peerIPs[host]; len(found) > 0 {
			return !slices.ContainsFunc(found, isReachable)
		}
		// Not in netmap. Tailnet-suffixed names are tailnet-intent but unresolvable (peer in the tailnet but no grant exposes it to this node, peer offline, or typo); everything else is non-Tailscale and out of scope.
		return dnsname.HasSuffix(host, magicDNSSuffixLower)
	}

	for suffix, rs := range dcfg.Routes {
		// In-place partition: reuse rs's backing array for survivors; collect drops separately for the diagnostic map.
		keep := rs[:0]
		var dropped []*dnstype.Resolver
		for _, r := range rs {
			if shouldDrop(r) {
				dropped = append(dropped, r)
			} else {
				keep = append(keep, r)
			}
		}
		if len(dropped) == 0 {
			continue
		}
		if filtered == nil {
			filtered = make(map[string][]*dnstype.Resolver)
		}
		filtered[suffix.WithoutTrailingDot()] = dropped
		if len(keep) == 0 {
			delete(dcfg.Routes, suffix)
		} else {
			dcfg.Routes[suffix] = keep
		}
	}
	return filtered
}

// peerIPsFromNetmap returns a map from lowercase, dot-stripped hostname to the IPs control associates with that hostname in nm. Self populates first so a DoH URL like https://self.<magic>/dns-query (a resolver on the local node) resolves to the loopback IPs; peers fill in next; ExtraRecords fill remaining gaps. The first source to claim a name wins.
func peerIPsFromNetmap(nm *netmap.NetworkMap) map[string][]netip.Addr {
	m := make(map[string][]netip.Addr, len(nm.Peers)+1)
	addHostname := func(rawName string, addrPfxs views.Slice[netip.Prefix]) {
		name := strings.TrimSuffix(strings.ToLower(rawName), ".")
		if name == "" || addrPfxs.Len() == 0 {
			return
		}
		if _, ok := m[name]; ok {
			return // first source wins; in real netmaps names are unique anyway
		}
		addrs := make([]netip.Addr, 0, addrPfxs.Len())
		for _, pfx := range addrPfxs.All() {
			addrs = append(addrs, pfx.Addr())
		}
		m[name] = addrs
	}
	if nm.SelfNode.Valid() {
		addHostname(nm.SelfNode.Name(), nm.SelfNode.Addresses())
	}
	for _, p := range nm.Peers {
		addHostname(p.Name(), p.Addresses())
	}
	for _, rec := range nm.DNS.ExtraRecords {
		if rec.Type != "" {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(rec.Name), ".")
		if name == "" {
			continue
		}
		if _, ok := m[name]; ok {
			continue // first source wins
		}
		if ip, err := netip.ParseAddr(rec.Value); err == nil {
			m[name] = []netip.Addr{ip}
		}
	}
	return m
}
