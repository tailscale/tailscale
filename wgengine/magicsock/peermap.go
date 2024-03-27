// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

// peerInfo is all the information magicsock tracks about a particular
// peer.
type peerInfo struct {
	ep *endpoint // always non-nil.
	// ipPorts is an inverted version of peerMap.byIPPort (below), so
	// that when we're deleting this node, we can rapidly find out the
	// keys that need deleting from peerMap.byIPPort without having to
	// iterate over every IPPort known for any peer.
	ipPorts set.Set[netip.AddrPort]
}

func newPeerInfo(ep *endpoint) *peerInfo {
	return &peerInfo{
		ep:      ep,
		ipPorts: set.Set[netip.AddrPort]{},
	}
}

// peerMap is an index of peerInfos by node (WireGuard) key, disco
// key, and discovered ip:port endpoints.
//
// It doesn't do any locking; all access must be done with Conn.mu held.
type peerMap struct {
	byNodeKey map[key.NodePublic]*peerInfo
	byIPPort  map[netip.AddrPort]*peerInfo
	byNodeID  map[tailcfg.NodeID]*peerInfo

	// nodesOfDisco contains the set of nodes that are using a
	// DiscoKey. Usually those sets will be just one node.
	nodesOfDisco map[key.DiscoPublic]set.Set[key.NodePublic]
}

func newPeerMap() peerMap {
	return peerMap{
		byNodeKey:    map[key.NodePublic]*peerInfo{},
		byIPPort:     map[netip.AddrPort]*peerInfo{},
		byNodeID:     map[tailcfg.NodeID]*peerInfo{},
		nodesOfDisco: map[key.DiscoPublic]set.Set[key.NodePublic]{},
	}
}

// nodeCount returns the number of nodes currently in m.
func (m *peerMap) nodeCount() int {
	if len(m.byNodeKey) != len(m.byNodeID) {
		devPanicf("internal error: peerMap.byNodeKey and byNodeID out of sync")
	}
	return len(m.byNodeKey)
}

// knownPeerDiscoKey reports whether there exists any peer with the disco key
// dk.
func (m *peerMap) knownPeerDiscoKey(dk key.DiscoPublic) bool {
	_, ok := m.nodesOfDisco[dk]
	return ok
}

// endpointForNodeKey returns the endpoint for nk, or nil if
// nk is not known to us.
func (m *peerMap) endpointForNodeKey(nk key.NodePublic) (ep *endpoint, ok bool) {
	if nk.IsZero() {
		return nil, false
	}
	if info, ok := m.byNodeKey[nk]; ok {
		return info.ep, true
	}
	return nil, false
}

// endpointForNodeID returns the endpoint for nodeID, or nil if
// nodeID is not known to us.
func (m *peerMap) endpointForNodeID(nodeID tailcfg.NodeID) (ep *endpoint, ok bool) {
	if info, ok := m.byNodeID[nodeID]; ok {
		return info.ep, true
	}
	return nil, false
}

// endpointForIPPort returns the endpoint for the peer we
// believe to be at ipp, or nil if we don't know of any such peer.
func (m *peerMap) endpointForIPPort(ipp netip.AddrPort) (ep *endpoint, ok bool) {
	if info, ok := m.byIPPort[ipp]; ok {
		return info.ep, true
	}
	return nil, false
}

// forEachEndpoint invokes f on every endpoint in m.
func (m *peerMap) forEachEndpoint(f func(ep *endpoint)) {
	for _, pi := range m.byNodeKey {
		f(pi.ep)
	}
}

// forEachEndpointWithDiscoKey invokes f on every endpoint in m that has the
// provided DiscoKey until f returns false or there are no endpoints left to
// iterate.
func (m *peerMap) forEachEndpointWithDiscoKey(dk key.DiscoPublic, f func(*endpoint) (keepGoing bool)) {
	for nk := range m.nodesOfDisco[dk] {
		pi, ok := m.byNodeKey[nk]
		if !ok {
			// Unexpected. Data structures would have to
			// be out of sync.  But we don't have a logger
			// here to log [unexpected], so just skip.
			// Maybe log later once peerMap is merged back
			// into Conn.
			continue
		}
		if !f(pi.ep) {
			return
		}
	}
}

// upsertEndpoint stores endpoint in the peerInfo for
// ep.publicKey, and updates indexes. m must already have a
// tailcfg.Node for ep.publicKey.
func (m *peerMap) upsertEndpoint(ep *endpoint, oldDiscoKey key.DiscoPublic) {
	if ep.nodeID == 0 {
		panic("internal error: upsertEndpoint called with zero NodeID")
	}
	pi, ok := m.byNodeKey[ep.publicKey]
	if !ok {
		pi = newPeerInfo(ep)
		m.byNodeKey[ep.publicKey] = pi
	}
	m.byNodeID[ep.nodeID] = pi

	epDisco := ep.disco.Load()
	if epDisco == nil || oldDiscoKey != epDisco.key {
		delete(m.nodesOfDisco[oldDiscoKey], ep.publicKey)
	}
	if ep.isWireguardOnly {
		// If the peer is a WireGuard only peer, add all of its endpoints.

		// TODO(raggi,catzkorn): this could mean that if a "isWireguardOnly"
		// peer has, say, 192.168.0.2 and so does a tailscale peer, the
		// wireguard one will win. That may not be the outcome that we want -
		// perhaps we should prefer bestAddr.AddrPort if it is set?
		// see tailscale/tailscale#7994
		for ipp := range ep.endpointState {
			m.setNodeKeyForIPPort(ipp, ep.publicKey)
		}
		return
	}
	discoSet := m.nodesOfDisco[epDisco.key]
	if discoSet == nil {
		discoSet = set.Set[key.NodePublic]{}
		m.nodesOfDisco[epDisco.key] = discoSet
	}
	discoSet.Add(ep.publicKey)
}

// setNodeKeyForIPPort makes future peer lookups by ipp return the
// same endpoint as a lookup by nk.
//
// This should only be called with a fully verified mapping of ipp to
// nk, because calling this function defines the endpoint we hand to
// WireGuard for packets received from ipp.
func (m *peerMap) setNodeKeyForIPPort(ipp netip.AddrPort, nk key.NodePublic) {
	if pi := m.byIPPort[ipp]; pi != nil {
		delete(pi.ipPorts, ipp)
		delete(m.byIPPort, ipp)
	}
	if pi, ok := m.byNodeKey[nk]; ok {
		pi.ipPorts.Add(ipp)
		m.byIPPort[ipp] = pi
	}
}

// deleteEndpoint deletes the peerInfo associated with ep, and
// updates indexes.
func (m *peerMap) deleteEndpoint(ep *endpoint) {
	if ep == nil {
		return
	}
	ep.stopAndReset()

	epDisco := ep.disco.Load()

	pi := m.byNodeKey[ep.publicKey]
	if epDisco != nil {
		delete(m.nodesOfDisco[epDisco.key], ep.publicKey)
	}
	delete(m.byNodeKey, ep.publicKey)
	if was, ok := m.byNodeID[ep.nodeID]; ok && was.ep == ep {
		delete(m.byNodeID, ep.nodeID)
	}
	if pi == nil {
		// Kneejerk paranoia from earlier issue 2801.
		// Unexpected. But no logger plumbed here to log so.
		return
	}
	for ip := range pi.ipPorts {
		delete(m.byIPPort, ip)
	}
}
