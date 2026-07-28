// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package traffic contains helpers for evaluating traffic steering scores and
// picking appropriate nodes.
package traffic

import (
	"cmp"
	"encoding/binary"
	"hash/fnv"
	"iter"
	"maps"
	"slices"

	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
)

// Score is a node’s traffic score, where any int could be a valid score.
// A higher traffic score suggests that the client should prefer that peer
// over one with a lower traffic score.
type Score int

// Scores is a memoization cache for the traffic scores of the current node’s peers.
type Scores struct {
	self tailcfg.NodeID
	hash NodeHasher

	scores map[tailcfg.NodeID]Score
}

// ScoresFor returns a new [Scores] cache for the current node’s ID,
// after scoring the peer nodes and adding these scores to the cache.
func ScoresFor(self tailcfg.NodeID, peers []tailcfg.NodeView) Scores {
	ss := Scores{
		self: self,
		hash: MakeRendezvousHasher(self),
	}
	ss.ScorePeers(peers)
	return ss
}

// IsValid reports whether ss has been initialized with the current node ID.
func (ss Scores) IsValid() bool {
	return !ss.self.IsZero()
}

// Score scores the given peer node and returns it after adding the score to the cache.
func (ss *Scores) Score(n tailcfg.NodeView) Score {
	id := n.ID()
	if s, ok := ss.scores[id]; ok {
		return s
	}

	var s Score
	if hi := n.Hostinfo(); hi.Valid() {
		if loc := hi.Location(); loc.Valid() {
			s = Score(loc.Priority())
		}
	}
	mak.Set(&ss.scores, id, s)
	return s
}

// ScorePeers scores the peer nodes and adds these scores to the cache.
func (ss *Scores) ScorePeers(peers []tailcfg.NodeView) {
	if len(peers) == 0 {
		return
	}
	if ss.scores == nil {
		ss.scores = make(map[tailcfg.NodeID]Score, len(peers))
	}
	for _, n := range peers {
		ss.Score(n)
	}
}

// All returns an iterator over the scores for every peer in the cache.
// The iteration order is not specified and is not guaranteed to be the same
// from one call to the next.
func (ss Scores) All() iter.Seq2[tailcfg.NodeID, Score] {
	return maps.All(ss.scores)
}

// SortNodes sorts the slice of nodes in descending order of [Scores.Score],
// using rendezvous hashing to break ties when both nodes have the same score.
// After sorting, the zeroth element is the preferred node.
func (ss Scores) SortNodes(nodes []tailcfg.NodeView) {
	slices.SortFunc(nodes, func(a, b tailcfg.NodeView) int {
		c := cmp.Compare(ss.Score(b), ss.Score(a)) // Highest score first.
		if c == 0 {
			return ss.hash.Compare(b.ID(), a.ID()) // Descending order.
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

		// FNV-1a is more modern and distributes bits more evenly,
		// so it is recommended by the designers.
		//
		// Note that we don’t use a global hasher and h.Reset
		// because this closure could be called concurrently.
		// This is cheap because hash/fnv doesn’t need to allocate.
		h := fnv.New64a()
		h.Write(b[:])
		return h.Sum64()
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
