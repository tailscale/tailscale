// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"strings"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine"
)

// lookupPeerByIP returns the node public key for the peer that owns the
// given IP address. It is the fast path for [Engine.SetPeerByIPPacketFunc],
// handling exact-IP matches against node addresses; subnet routes and exit
// nodes are handled by a BART-based fallback in userspaceEngine that uses
// the wireguard-filtered peer list (see lastCfgFull).
//
// It is called by wireguard-go on every outbound packet (not cached), so
// it must be fast.
func (b *LocalBackend) lookupPeerByIP(ip netip.Addr) (key.NodePublic, bool) {
	nb := b.currentNode()
	nid, ok := nb.NodeByAddr(ip)
	if !ok {
		return key.NodePublic{}, false
	}
	peer, ok := nb.NodeByID(nid)
	if !ok {
		return key.NodePublic{}, false
	}
	return peer.Key(), true
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

// peerForIP returns which peer is responsible for a given IP address.
// Despite the name, it can also return the self node (with IsSelf set).
// It handles both Tailscale IPs (returning the owning peer or self) and
// non-Tailscale addresses like subnet-routed IPs or exit-node global
// internet IPs (returning whichever peer would route that traffic).
// It is installed as the [wgengine.Engine.SetPeerForIPFunc] callback.
func (b *LocalBackend) peerForIP(ip netip.Addr) (_ wgengine.PeerForIP, ok bool) {
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

	pk, route, ok := b.e.PeerKeyForIP(ip)
	if !ok {
		return wgengine.PeerForIP{}, false
	}
	nid, ok := nb.NodeByKey(pk)
	if !ok {
		return wgengine.PeerForIP{}, false
	}
	n, ok := nb.NodeByID(nid)
	if !ok {
		return wgengine.PeerForIP{}, false
	}
	return wgengine.PeerForIP{Node: n, Route: route}, true
}
