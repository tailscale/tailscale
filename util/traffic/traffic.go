// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package traffic contains helpers for evaluating traffic steering scores and
// picking appropriate nodes.
package traffic

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"tailscale.com/tailcfg"
)

// Scores is a memoization cache for the traffic scores of the current node’s peers.
// A higher traffic score suggests that the client should prefer that peer
// over one with a lower traffic score. Any int could be a valid score.
type Scores map[tailcfg.NodeID]int

// ScorePeers scores the peer nodes and returns the cache that memoized these scores.
func ScorePeers(peers []tailcfg.NodeView) Scores {
	ss := make(Scores, len(peers))
	for _, n := range peers {
		ss.Add(n)
	}
	return ss
}

// Add scores the given peer node and returns it after adding the score to the cache.
// It also reports whether the score had to be added because it was missing.
func (ss Scores) Add(n tailcfg.NodeView) (score int, added bool) {
	id := n.ID()
	s, ok := ss[id]
	if !ok {
		s := 0 // score of zero means incomparable
		if hi := n.Hostinfo(); hi.Valid() {
			if loc := hi.Location(); loc.Valid() {
				s = loc.Priority()
			}
		}
		ss[id] = s
	}
	return s, ok
}

// Score scores the given peer node and returns it after adding the score to the cache.
func (ss Scores) Score(n tailcfg.NodeView) int {
	s, _ := ss.Add(n)
	return s
}

// SortNodes sorts the slice of nodes in descending order of [Scores.Score],
// using the tiebreak function to break ties when both nodes have the same score.
// After sorting, the zeroth element is the preferred node.
//
// tiebreak(a, b) should return a negative number when a < b and a positive number when a > b;
// it should never return zero to guarantee a stable ordering.
func (ss Scores) SortNodes(nodes []tailcfg.NodeView, tiebreak func(a, b tailcfg.NodeView) int) {
	slices.SortFunc(nodes, func(a, b tailcfg.NodeView) int {
		c := cmp.Compare(ss.Score(b), ss.Score(a)) // Highest score first.
		if c == 0 {
			return tiebreak(b, a) // Highest tiebreak first.
		}
		return c
	})
}

// NodeHasher returns a 64-bit hash of a node ID.
type NodeHasher func(tailcfg.NodeID) uint64

// MakeRendezvousHasher returns a function that hashes a node ID to a uint64.
// https://en.wikipedia.org/wiki/Rendezvous_hashing
func MakeRendezvousHasher(seed tailcfg.NodeID) NodeHasher {
	en := binary.BigEndian
	return func(n tailcfg.NodeID) uint64 {
		var b [16]byte
		en.PutUint64(b[:], uint64(seed))
		en.PutUint64(b[8:], uint64(n))
		v := sha256.Sum256(b[:])
		return en.Uint64(v[:])
	}
}

// Compare compares the node ID hashes of peers a and b, using the same convention as [cmp.Compare].
// Since h is seeded with the current node’s ID, the ordering between a and b will remain stable
// for this node; but the order may flip for when h is seeded for another node.
// This function should return zero, if and only if a and b have the same node ID.
func (h NodeHasher) Compare(a, b tailcfg.NodeID) int {
	c := cmp.Compare(h(a), h(b))
	if c == 0 {
		// In the unlikely event of a hash collision, compare the actual IDs.
		return cmp.Compare(a, b)
	}
	return c
}
