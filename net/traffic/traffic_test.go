// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package traffic_test

import (
	"maps"
	"math/rand/v2"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"tailscale.com/net/traffic"
	"tailscale.com/tailcfg"
)

// WantScores is a convenience alias for the type of [traffic.Score.scores].
type wantScores = map[tailcfg.NodeID]traffic.Score

var scoresCases = []struct {
	name  string
	peers []*tailcfg.Node
	want  wantScores
}{
	{
		name:  "none",
		peers: nil,
		want:  wantScores{},
	},
	{
		name: "no-scores",
		peers: []*tailcfg.Node{
			{ID: 37},
			{ID: 42},
		},
		want: wantScores{
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
		want: wantScores{
			37: 0,
			42: 1,
		},
	},
}

func TestScoreOne(t *testing.T) {
	for _, tc := range scoresCases {
		if len(tc.peers) == 0 {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			selfID := tailcfg.NodeID(1)
			ss := traffic.ScoresFor(selfID, nil)
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
			got := maps.Collect(ss.All())
			if diff := gocmp.Diff(tc.want, got); diff != "" {
				t.Errorf("-want +got:\n%s", diff)
			}
		})
	}
}

func TestScoreMany(t *testing.T) {
	for _, tc := range scoresCases {
		t.Run(tc.name, func(t *testing.T) {
			selfID := tailcfg.NodeID(1)
			var peers []tailcfg.NodeView
			for _, n := range tc.peers {
				peers = append(peers, n.View())
			}

			t.Run("ScoresFor", func(t *testing.T) {
				ss := traffic.ScoresFor(selfID, peers)
				got := maps.Collect(ss.All())
				if diff := gocmp.Diff(tc.want, got); diff != "" {
					t.Errorf("-want +got:\n%s", diff)
				}
			})

			t.Run("ScorePeers", func(t *testing.T) {
				ss := traffic.ScoresFor(selfID, nil)
				ss.ScorePeers(peers)
				got := maps.Collect(ss.All())
				if diff := gocmp.Diff(tc.want, got); diff != "" {
					t.Errorf("-want +got:\n%s", diff)
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

// FuzzSortNodes tests that nodes are sorted such that every node
// with an equal score has an equal chance of being first.
func FuzzSortNodes(f *testing.F) {
	nodeIDs := func(nodes []tailcfg.NodeView) []tailcfg.NodeID {
		nids := make([]tailcfg.NodeID, len(nodes))
		for i, n := range nodes {
			nids[i] = n.ID()
		}
		return nids
	}

	for _, seed := range [][]uint64{
		{0, 0},
		{1, 2},
		{37, 42},
		{5376970906336561236, 2417489263451880030},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
		t.Logf("using random seeds %d %d", seed1, seed2)
		rnd := rand.New(rand.NewPCG(seed1, seed2))

		wantScore := traffic.Score(rnd.IntN(2000))

		// Create a reasonably large tailnet, between 20 and 40 nodes.
		// If the number of nodes is too small, the chances of one node
		// getting ranked best becomes non-trivial.
		nodes := make([]tailcfg.NodeView, rnd.IntN(20)+20)
		for i := range len(nodes) {
			n := tailcfg.Node{
				ID: tailcfg.NodeID(rnd.Int64()),
				Hostinfo: (&tailcfg.Hostinfo{
					Location: &tailcfg.Location{
						Priority: int(wantScore),
					},
				}).View(),
			}
			nodes[i] = n.View()
		}
		t.Logf("node ids: %v", nodeIDs(nodes))

		// All scores should be the same.
		ss := traffic.ScoresFor(nodes[0].ID(), nodes)
		for _, n := range nodes {
			s := ss.Score(n)
			if s != wantScore {
				t.Errorf("%s: score %d, want %d", n.ID(), s, wantScore)
			}
		}

		// Sort nodes from the point-of-view of each node and ensure that
		// every node is equally represented by ensuring one node isn’t
		// sorted highest too often.
		best := make(map[tailcfg.NodeID][]tailcfg.NodeID, len(nodes))
		for i := range len(nodes) {
			peers := slices.Clone(nodes)
			selfID := peers[i].ID()
			ss := traffic.ScoresFor(selfID, peers)
			ss.SortNodes(peers)
			t.Logf("self %s, sorted %v", selfID, nodeIDs(peers))
			bestID := peers[0].ID()
			best[bestID] = append(best[bestID], selfID)
		}
		for nid, selfIDs := range best {
			if count := len(selfIDs); count > len(nodes)/2 {
				t.Errorf("%s is best too frequently: %d", nid, selfIDs)
				t.Fatalf("best map: %v", best)
			}
		}
	})
}
