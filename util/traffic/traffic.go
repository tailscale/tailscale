// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package traffic contains helpers for evaluating traffic steering scores and
// picking appropriate nodes.
package traffic

import (
	"crypto/sha256"
	"encoding/binary"

	"tailscale.com/tailcfg"
)

// Scores is a memoization cache for the traffic scores of the current node’s peers.
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

// MakeRendezvousHasher returns a function that hashes a node ID to a uint64.
// https://en.wikipedia.org/wiki/Rendezvous_hashing
func MakeRendezvousHasher(seed tailcfg.NodeID) func(tailcfg.NodeID) uint64 {
	en := binary.BigEndian
	return func(n tailcfg.NodeID) uint64 {
		var b [16]byte
		en.PutUint64(b[:], uint64(seed))
		en.PutUint64(b[8:], uint64(n))
		v := sha256.Sum256(b[:])
		return en.Uint64(v[:])
	}
}
