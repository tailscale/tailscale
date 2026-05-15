// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package traffic_test

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"tailscale.com/tailcfg"
	"tailscale.com/util/traffic"
)

var scoresCases = []struct {
	name  string
	peers []*tailcfg.Node
	want  traffic.Scores
}{
	{
		name:  "none",
		peers: nil,
		want:  nil,
	},
	{
		name: "no-scores",
		peers: []*tailcfg.Node{
			{ID: 37},
			{ID: 42},
		},
		want: traffic.Scores{
			37: 0,
			42: 0,
		},
	},
	{
		name: "mixed-scores",
		peers: []*tailcfg.Node{
			{ID: 37},
			{
				ID: 42,
				Hostinfo: (&tailcfg.Hostinfo{
					Location: &tailcfg.Location{Priority: 1},
				}).View(),
			},
		},
		want: traffic.Scores{
			37: 0,
			42: 1,
		},
	},
}

func TestScorePeers(t *testing.T) {
	for _, tc := range scoresCases {
		t.Run(tc.name, func(t *testing.T) {
			var peers []tailcfg.NodeView
			for _, n := range tc.peers {
				peers = append(peers, n.View())
			}
			got := traffic.ScorePeers(peers)
			if diff := gocmp.Diff(tc.want, got); diff != "" {
				t.Errorf("-want +got:\n%s", diff)
			}
		})
	}
}

func TestScoresAdd(t *testing.T) {
	for _, tc := range scoresCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("Add", func(t *testing.T) {
				var ss traffic.Scores
				for _, n := range tc.peers {
					want := tc.want[n.ID]
					score, added := ss.Add(n.View())
					if score != want || !added {
						t.Errorf("initial Add for nodeid:%d: score %d, want %d; added %t, want true", n.ID, score, want, added)
					}
					score, added = ss.Add(n.View())
					if score != want || added {
						t.Errorf("subsequent Add for nodeid:%d: score %d, want %d; added %t, want false", n.ID, score, want, added)
					}
				}
				if diff := gocmp.Diff(tc.want, ss); diff != "" {
					t.Errorf("-want +ss:\n%s", diff)
				}
			})

			t.Run("Score", func(t *testing.T) {
				var ss traffic.Scores
				for _, n := range tc.peers {
					want := tc.want[n.ID]
					score := ss.Score(n.View())
					if score != want {
						t.Errorf("initial Score for nodeid:%d: score %d, want %d", n.ID, score, want)
					}
					score = ss.Score(n.View())
					if score != want {
						t.Errorf("subsequent Score for nodeid:%d: score %d, want %d", n.ID, score, want)
					}
				}
				if diff := gocmp.Diff(tc.want, ss); diff != "" {
					t.Errorf("-want +ss:\n%s", diff)
				}
			})
		})
	}
}

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
