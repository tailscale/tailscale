// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package traffic

import (
	"math"
	"math/rand/v2"
	"slices"
	"testing"

	"tailscale.com/tailcfg"
)

func FuzzNodeHasherCompare(f *testing.F) {
	for _, seed := range [][]uint64{
		{0, 0, 0},
		{1, 1, 1},
		{1, 10, 11},
		{1, 11, 10},
		{2, 10, 11},
	} {
		selfID, aID, bID := seed[0], seed[1], seed[2]
		f.Add(selfID, aID, bID)
	}

	f.Fuzz(func(t *testing.T, selfID, aID, bID uint64) {
		h := MakeRendezvousHasher(tailcfg.NodeID(selfID))
		a, b := tailcfg.NodeID(aID), tailcfg.NodeID(bID)
		c := h.Compare(a, b)
		if c == 0 && a != b {
			t.Fatalf("got %d: expected different hashes because a ≠ b, ", c)
		}
		if cc := h.Compare(a, b); c != cc {
			t.Fatalf("c %d, cc %d: expected matching values", c, cc)
		}
		if d := h.Compare(b, a); c != -d {
			t.Fatalf("c %d, d %d: expected inverse values", c, d)
		}
	})
}

// FuzzSortNodes tests that nodes are sorted such that every node
// with an equal score has an equal chance of being first.
func FuzzSortNodes(f *testing.F) {
	for _, seed := range [][]uint64{
		{0, 0},
		{1, 2},
		{37, 42},
		{5376970906336561236, 2417489263451880030},
	} {
		f.Add(seed[0], seed[1])
	}

	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		rnd := rand.New(rand.NewPCG(seed1, seed2))

		wantScore := Score(rnd.IntN(2000))

		// Create a reasonably large tailnet.
		// If the number of nodes is too small, the chances of one node
		// getting ranked best becomes non-trivial.
		clients := make([]tailcfg.NodeView, 10_000)
		for i := range len(clients) {
			n := tailcfg.Node{
				ID: tailcfg.NodeID(rnd.Int64()),
			}
			clients[i] = n.View()
		}

		// Smaller number of candidates, crossing some power of
		// two boundaries to ensure most-significant-bits don't skew
		// the hash output distribution.
		candidates := make([]tailcfg.NodeView, rnd.IntN(16)+1)
		for i := range len(candidates) {
			n := tailcfg.Node{
				ID: tailcfg.NodeID(rnd.Int64()),
				Hostinfo: (&tailcfg.Hostinfo{
					Location: &tailcfg.Location{
						Priority: int(wantScore),
					},
				}).View(),
			}
			candidates[i] = n.View()
		}

		// All scores should be the same.
		ss := ScoresFor(clients[0].ID(), candidates)
		for _, n := range candidates {
			s := ss.Score(n)
			if s != wantScore {
				t.Errorf("%s: score %d, want %d", n.ID(), s, wantScore)
			}
		}

		// Map each candidate to the number of clients that it was the best candidate for
		best := make(map[tailcfg.NodeID]int, len(candidates))
		for i := range len(clients) {
			peers := slices.Clone(candidates)
			selfID := clients[i].ID()
			ss := ScoresFor(selfID, peers)
			ss.SortNodes(peers)
			bestID := peers[0].ID()
			best[bestID]++
		}

		// 20% margin off perfect fairness
		fair := float64(len(clients)) / float64(len(candidates))
		lo, hi := math.Floor(fair*0.8), math.Ceil(fair*1.2)

		for candidateID, count := range best {
			if float64(count) < lo || float64(count) > hi {
				t.Logf("total clients %d; total candidates %d; fair %f", len(clients), len(candidates), fair)
				t.Errorf("%s is best too frequently: %d", candidateID, count)
				t.Fatalf("best map: %v", best)
			}
		}
	})
}
