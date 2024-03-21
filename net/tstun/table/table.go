// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package table provides a Routing Table implementation which allows
// looking up the peer that should be used to route a given IP address.
package table

import (
	"net/netip"

	"github.com/gaissmai/bart"
	"tailscale.com/types/key"
	"tailscale.com/util/mak"
)

// RoutingTableBuilder is a builder for a RoutingTable.
// It is not safe for concurrent use.
type RoutingTableBuilder struct {
	// peers is a map from node public key to the peer that owns that key.
	// It is only used to handle insertions and deletions.
	peers map[key.NodePublic][]netip.Prefix

	// table is a routing table that supports longest prefix matches on IP
	// ip addresses. This facilitates looking up the peer that owns a given IP
	// address.
	table bart.Table[key.NodePublic]
}

// InsertOrReplace inserts the given peer and prefixes into the routing table.
func (t *RoutingTableBuilder) InsertOrReplace(peer key.NodePublic, pfxs ...netip.Prefix) {
	oldPfxs, found := t.peers[peer]
	if found {
		for _, pfx := range oldPfxs {
			t.table.Delete(pfx)
		}
	}
	if len(pfxs) == 0 {
		return
	}
	mak.Set(&t.peers, peer, pfxs)
	for _, pfx := range pfxs {
		t.table.Insert(pfx, peer)
	}
}

// Build returns a RoutingTable that can be used to look up peers.
// Build resets the RoutingTableBuilder to its zero value.
func (t *RoutingTableBuilder) Build() *RoutingTable {
	return &RoutingTable{
		table: &t.table,
	}
}

// RoutingTable provides a mapping from IP addresses to peers identified by
// their public node key. It is used to find the peer that should be used to
// route a given IP address.
// It is immutable after creation.
//
// It is safe for concurrent use.
type RoutingTable struct {
	table *bart.Table[key.NodePublic]
}

// Lookup returns the peer that would be used to route the given IP address.
// If no peer is found, Lookup returns the zero value.
func (t *RoutingTable) Lookup(ip netip.Addr) (_ key.NodePublic, ok bool) {
	if t == nil {
		return key.NodePublic{}, false
	}
	_, k, found := t.table.Lookup(ip)
	if !found {
		return key.NodePublic{}, false
	}
	return k, true
}
