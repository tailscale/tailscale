// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

// peerInfo is all the information magicsock tracks about a particular
// peer.
type peerInfo struct {
	ep *endpoint // always non-nil.
	// epAddrs is an inverted version of peerMap.byEpAddr (below), so
	// that when we're deleting this node, we can rapidly find out the
	// keys that need deleting from peerMap.byEpAddr without having to
	// iterate over every epAddr known for any peer.
	epAddrs set.Set[epAddr]
}

func newPeerInfo(ep *endpoint) *peerInfo {
	return &peerInfo{
		ep:      ep,
		epAddrs: set.Set[epAddr]{},
	}
}

// peerMap is an index of peerInfos by node (WireGuard) key, disco
// key, and discovered ip:port endpoints.
//
// It doesn't do any locking; all access must be done with Conn.mu held.
type peerMap struct {
	byNodeKey map[key.NodePublic]*peerInfo
	byEpAddr  map[epAddr]*peerInfo
	byNodeID  map[tailcfg.NodeID]*peerInfo

	// relayEpAddrByNodeKey ensures we only hold a single relay
	// [epAddr] (vni.isSet()) for a given node key in byEpAddr, vs letting them
	// grow unbounded. Relay [epAddr]'s are dynamically created by
	// [relayManager] during path discovery, and are only useful to track in
	// peerMap so long as they are the endpoint.bestAddr. [relayManager] handles
	// all creation and initial probing responsibilities otherwise, and it does
	// not depend on [peerMap].
	//
	// Note: This doesn't address unbounded growth of non-relay epAddr's in
	// byEpAddr. That issue is being tracked in http://go/corp/29422.
	relayEpAddrByNodeKey map[key.NodePublic]epAddr

	// nodesOfDisco contains the set of nodes that are using a
	// DiscoKey. Usually those sets will be just one node.
	nodesOfDisco map[key.DiscoPublic]set.Set[key.NodePublic]
}

func newPeerMap() peerMap {
	return peerMap{
		byNodeKey:            map[key.NodePublic]*peerInfo{},
		byEpAddr:             map[epAddr]*peerInfo{},
		byNodeID:             map[tailcfg.NodeID]*peerInfo{},
		relayEpAddrByNodeKey: map[key.NodePublic]epAddr{},
		nodesOfDisco:         map[key.DiscoPublic]set.Set[key.NodePublic]{},
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

// endpointForEpAddr returns the endpoint for the peer we
// believe to be at addr, or nil if we don't know of any such peer.
func (m *peerMap) endpointForEpAddr(addr epAddr) (ep *endpoint, ok bool) {
	if info, ok := m.byEpAddr[addr]; ok {
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
		// perhaps we should prefer bestAddr.epAddr.ap if it is set?
		// see tailscale/tailscale#7994
		for ipp := range ep.endpointState {
			m.setNodeKeyForEpAddr(epAddr{ap: ipp}, ep.publicKey)
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

// setNodeKeyForEpAddr makes future peer lookups by addr return the
// same endpoint as a lookup by nk.
//
// This should only be called with a fully verified mapping of addr to
// nk, because calling this function defines the endpoint we hand to
// WireGuard for packets received from addr.
func (m *peerMap) setNodeKeyForEpAddr(addr epAddr, nk key.NodePublic) {
	if pi := m.byEpAddr[addr]; pi != nil {
		delete(pi.epAddrs, addr)
		delete(m.byEpAddr, addr)
		if addr.vni.isSet() {
			delete(m.relayEpAddrByNodeKey, pi.ep.publicKey)
		}
	}
	if pi, ok := m.byNodeKey[nk]; ok {
		if addr.vni.isSet() {
			relay, ok := m.relayEpAddrByNodeKey[nk]
			if ok {
				delete(pi.epAddrs, relay)
				delete(m.byEpAddr, relay)
			}
			m.relayEpAddrByNodeKey[nk] = addr
		}
		pi.epAddrs.Add(addr)
		m.byEpAddr[addr] = pi
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
	for ip := range pi.epAddrs {
		delete(m.byEpAddr, ip)
	}
	delete(m.relayEpAddrByNodeKey, ep.publicKey)
}
