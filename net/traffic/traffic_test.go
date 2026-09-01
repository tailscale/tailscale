// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package traffic_test

import (
	"maps"
	"testing"
	"testing/quick"

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


func TestMakeRendezvousHasher(t *testing.T) {
	t.Run("new-hasher", func(t *testing.T) {
		f := func(from, to tailcfg.NodeID) uint64 {
			h := traffic.MakeRendezvousHasher(from)
			return h(to)
		}
		if err := quick.CheckEqual(f, f, nil); err != nil {
			t.Error(err)
		}
	})

	t.Run("same-hasher", func(t *testing.T) {
		f := func(from, to tailcfg.NodeID) bool {
			h := traffic.MakeRendezvousHasher(from)
			first := h(to)
			second := h(to)
			return first == second
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})
}
