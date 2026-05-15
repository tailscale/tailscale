// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package traffic_test

import (
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/util/traffic"
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
		t.Logf("selfID %d, aID %d, bID %d", selfID, aID, bID)
		h := traffic.MakeRendezvousHasher(tailcfg.NodeID(selfID))
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
