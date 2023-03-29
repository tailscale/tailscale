// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package table provides a Routing Table implementation which allows
// looking up the peer that should be used to route a given IP address.
package table

import (
	"net/netip"

	"tailscale.com/tempfork/device"
	"tailscale.com/types/key"
	"tailscale.com/util/mak"
)

// RoutingTableBuilder is a builder for a RoutingTable.
// It is not safe for concurrent use.
type RoutingTableBuilder struct {
	// peers is a map from node public key to the peer that owns that key.
	// It is only used to handle insertions and deletions.
	peers map[key.NodePublic]*device.Peer

	// prefixTrie is a trie of prefixes which facilitates looking up the
	// peer that owns a given IP address.
	prefixTrie *device.AllowedIPs
}

// Remove removes the given peer from the routing table.
func (t *RoutingTableBuilder) Remove(peer key.NodePublic) {
	p, ok := t.peers[peer]
	if !ok {
		return
	}
	t.prefixTrie.RemoveByPeer(p)
	delete(t.peers, peer)
}

// InsertOrReplace inserts the given peer and prefixes into the routing table.
func (t *RoutingTableBuilder) InsertOrReplace(peer key.NodePublic, pfxs ...netip.Prefix) {
	p, ok := t.peers[peer]
	if !ok {
		p = device.NewPeer(peer)
		mak.Set(&t.peers, peer, p)
	} else {
		t.prefixTrie.RemoveByPeer(p)
	}
	if len(pfxs) == 0 {
		return
	}
	if t.prefixTrie == nil {
		t.prefixTrie = new(device.AllowedIPs)
	}
	for _, pfx := range pfxs {
		t.prefixTrie.Insert(pfx, p)
	}
}

// Build returns a RoutingTable that can be used to look up peers.
// Build resets the RoutingTableBuilder to its zero value.
func (t *RoutingTableBuilder) Build() *RoutingTable {
	pt := t.prefixTrie
	t.prefixTrie = nil
	t.peers = nil
	return &RoutingTable{
		prefixTrie: pt,
	}
}

// RoutingTable provides a mapping from IP addresses to peers identified by
// their public node key. It is used to find the peer that should be used to
// route a given IP address.
// It is immutable after creation.
//
// It is safe for concurrent use.
type RoutingTable struct {
	prefixTrie *device.AllowedIPs
}

// Lookup returns the peer that would be used to route the given IP address.
// If no peer is found, Lookup returns the zero value.
func (t *RoutingTable) Lookup(ip netip.Addr) (_ key.NodePublic, ok bool) {
	if t == nil {
		return key.NodePublic{}, false
	}
	p := t.prefixTrie.Lookup(ip.AsSlice())
	if p == nil {
		return key.NodePublic{}, false
	}
	return p.Key(), true
}
