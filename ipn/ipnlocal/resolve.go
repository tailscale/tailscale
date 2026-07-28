// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"strings"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine"
)

// lookupPeerByIP returns the node public key for the peer that should
// handle traffic to the given IP address. It is installed as the
// [wgengine.Engine.SetPeerByIPPacketFunc] callback: exact node
// addresses hit the nodeByAddr fast path, and subnet routes and
// exit-node default routes fall back to the RouteManager's outbound
// table, so it stays correct under incremental netmap deltas.
//
// It is called by wireguard-go on every outbound packet (not cached),
// so it must be fast.
func (b *LocalBackend) lookupPeerByIP(ip netip.Addr) (key.NodePublic, bool) {
	nb := b.currentNode()
	if nid, ok := nb.NodeByAddr(ip); ok {
		peer, ok := nb.NodeByID(nid)
		if !ok {
			return key.NodePublic{}, false
		}
		return peer.Key(), true
	}
	if pr, ok := nb.routeMgr.Outbound().Lookup(ip); ok {
		return pr.Key, true
	}
	return key.NodePublic{}, false
}

// peerAllowedIPs returns the prefixes from which the peer with the
// given public key is currently allowed to originate traffic, or
// ok=false if the peer is unknown (or currently routable via no
// prefix at all). It is installed as the
// [wgengine.Engine.SetPeerConfigFunc] callback, backing wireguard-go's
// lazy peer creation and per-delta peer sync.
func (b *LocalBackend) peerAllowedIPs(k key.NodePublic) (_ []netip.Prefix, ok bool) {
	return b.currentNode().PeerAllowedIPs(k)
}

// resolveMagicDNS resolves a MagicDNS hostname to the owning node's IP
// address, respecting the requested network address family ("tcp4",
// "tcp6", "tcp", etc.). It accepts peer FQDNs ("foo.tail-scale.ts.net"),
// short names ("foo"), and DNS.ExtraRecords entries (service VIPs).
// The hostname must be lowercase with no trailing dot. It is installed
// as the [tsdial.Dialer.SetResolveMagicDNS] callback.
func (b *LocalBackend) resolveMagicDNS(hostname, network string) (_ netip.Addr, ok bool) {
	nb := b.currentNode()
	if nid, ok := nb.NodeByName(hostname); ok {
		n, ok := nb.NodeByID(nid)
		if !ok {
			b.logf("[unexpected] resolveMagicDNS: NodeByName(%q) returned node %v but NodeByID failed", hostname, nid)
			return netip.Addr{}, false
		}
		if ip, ok := nodeAddrForNetwork(n, network); ok {
			return ip, true
		}
		return netip.Addr{}, false
	}
	if ip, ok := nb.ExtraDNSByName(hostname); ok && addrFamilyMatch(ip, network) {
		return ip, true
	}
	return netip.Addr{}, false
}

// magicDNSHosts implements [resolver.MagicDNSHosts] on top of the
// current nodeBackend's live node indexes, so the quad-100 resolver
// pulls each MagicDNS answer on demand rather than LocalBackend
// pushing a Hosts map of every node into it on every netmap change.
// It is installed once at LocalBackend construction; going through
// currentNode makes profile switches take effect immediately.
type magicDNSHosts struct{ b *LocalBackend }

func (m magicDNSHosts) LookupHost(fqdn dnsname.FQDN) (ips []netip.Addr, ok bool) {
	if !buildfeatures.HasDNS {
		return nil, false
	}
	return m.b.currentNode().magicDNSHostAddrs(fqdn)
}

func (m magicDNSHosts) LookupPTR(ip netip.Addr) (_ dnsname.FQDN, ok bool) {
	if !buildfeatures.HasDNS {
		return "", false
	}
	return m.b.currentNode().magicDNSPTR(ip)
}

func (m magicDNSHosts) SubdomainHost(fqdn dnsname.FQDN) bool {
	if !buildfeatures.HasDNS {
		return false
	}
	return m.b.currentNode().magicDNSSubdomainHost(fqdn)
}

var _ resolver.MagicDNSHosts = magicDNSHosts{}

// nodeAddrForNetwork returns the best address from n for the given
// network ("tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"). For
// unqualified networks ("tcp", "udp"), it prefers IPv4.
func nodeAddrForNetwork(n tailcfg.NodeView, network string) (_ netip.Addr, ok bool) {
	addrs := n.Addresses()
	if addrs.Len() == 0 {
		return netip.Addr{}, false
	}
	want4 := strings.HasSuffix(network, "4")
	want6 := strings.HasSuffix(network, "6")
	var v6 netip.Addr
	for _, pfx := range addrs.All() {
		ip := pfx.Addr()
		if want4 && ip.Is4() {
			return ip, true
		}
		if want6 && ip.Is6() {
			return ip, true
		}
		if !want4 && !want6 {
			if ip.Is4() {
				return ip, true
			}
			if !v6.IsValid() {
				v6 = ip
			}
		}
	}
	if v6.IsValid() {
		return v6, true
	}
	return netip.Addr{}, false
}

// addrFamilyMatch reports whether ip is compatible with the requested
// network address family.
func addrFamilyMatch(ip netip.Addr, network string) bool {
	if strings.HasSuffix(network, "4") {
		return ip.Is4()
	}
	if strings.HasSuffix(network, "6") {
		return ip.Is6()
	}
	return true
}

// PeerForIP returns which peer is responsible for a given IP address.
// Despite the name, it can also return the self node (with IsSelf set).
// It handles both Tailscale IPs (returning the owning peer or self) and
// non-Tailscale addresses like subnet-routed IPs or exit-node global
// internet IPs (returning whichever peer would route that traffic).
// It is installed as the [wgengine.Engine.SetPeerForIPFunc] callback,
// serving the engine's internal cold-path lookups (Ping, TSMP, pendopen
// diagnostics).
func (b *LocalBackend) PeerForIP(ip netip.Addr) (_ wgengine.PeerForIP, ok bool) {
	nb := b.currentNode()

	if tsaddr.IsTailscaleIP(ip) {
		if nid, ok := nb.NodeByAddr(ip); ok {
			n, ok := nb.NodeByID(nid)
			if !ok {
				b.logf("[unexpected] peerForIP: NodeByAddr(%v) returned node %v but NodeByID failed", ip, nid)
				return wgengine.PeerForIP{}, false
			}
			self := nb.Self()
			return wgengine.PeerForIP{
				Node:   n,
				IsSelf: self.Valid() && self.ID() == nid,
				Route:  netip.PrefixFrom(ip, ip.BitLen()),
			}, true
		}
	}

	route, pr, ok := nb.routeMgr.Outbound().LookupPrefixLPM(netip.PrefixFrom(ip, ip.BitLen()))
	if !ok {
		return wgengine.PeerForIP{}, false
	}
	nid, ok := nb.NodeByKey(pr.Key)
	if !ok {
		return wgengine.PeerForIP{}, false
	}
	n, ok := nb.NodeByID(nid)
	if !ok {
		return wgengine.PeerForIP{}, false
	}
	return wgengine.PeerForIP{Node: n, Route: route}, true
}
