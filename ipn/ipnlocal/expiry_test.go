// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestFlagExpiredPeers(t *testing.T) {
	n := func(id tailcfg.NodeID, name string, expiry time.Time, mod ...func(*tailcfg.Node)) *tailcfg.Node {
		n := &tailcfg.Node{ID: id, Name: name, KeyExpiry: expiry}
		for _, f := range mod {
			f(n)
		}
		return n
	}

	now := time.Unix(1673373129, 0)

	timeInPast := now.Add(-1 * time.Hour)
	timeInFuture := now.Add(1 * time.Hour)

	timeBeforeEpoch := flagExpiredPeersEpoch.Add(-1 * time.Second)
	if now.Before(timeBeforeEpoch) {
		panic("current time in test cannot be before epoch")
	}

	var expiredKey key.NodePublic
	if err := expiredKey.UnmarshalText([]byte("nodekey:6da774d5d7740000000000000000000000000000000000000000000000000000")); err != nil {
		panic(err)
	}

	tests := []struct {
		name        string
		controlTime *time.Time
		netmap      *netmap.NetworkMap
		want        []tailcfg.NodeView
	}{
		{
			name:        "no_expiry",
			controlTime: &now,
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", timeInFuture),
					n(2, "bar", timeInFuture),
				}),
			},
			want: nodeViews([]*tailcfg.Node{
				n(1, "foo", timeInFuture),
				n(2, "bar", timeInFuture),
			}),
		},
		{
			name:        "expiry",
			controlTime: &now,
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", timeInFuture),
					n(2, "bar", timeInPast),
				}),
			},
			want: nodeViews([]*tailcfg.Node{
				n(1, "foo", timeInFuture),
				n(2, "bar", timeInPast, func(n *tailcfg.Node) {
					n.Expired = true
					n.Key = expiredKey
				}),
			}),
		},
		{
			name: "bad_ControlTime",
			// controlTime here is intentionally before our hardcoded epoch
			controlTime: &timeBeforeEpoch,

			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", timeInFuture),
					n(2, "bar", timeBeforeEpoch.Add(-1*time.Hour)), // before ControlTime
				}),
			},
			want: nodeViews([]*tailcfg.Node{
				n(1, "foo", timeInFuture),
				n(2, "bar", timeBeforeEpoch.Add(-1*time.Hour)), // should have expired, but ControlTime is before epoch
			}),
		},
		{
			name:        "tagged_node",
			controlTime: &now,
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", timeInFuture),
					n(2, "bar", time.Time{}), // tagged node; zero expiry
				}),
			},
			want: nodeViews([]*tailcfg.Node{
				n(1, "foo", timeInFuture),
				n(2, "bar", time.Time{}), // not expired
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bus := eventbustest.NewBus(t)
			em := newExpiryManager(t.Logf, bus)
			em.clock = tstest.NewClock(tstest.ClockOpts{Start: now})
			if tt.controlTime != nil {
				em.onControlTime(*tt.controlTime)
			}
			em.flagExpiredPeers(tt.netmap, now)
			if !reflect.DeepEqual(tt.netmap.Peers, tt.want) {
				t.Errorf("wrong results\n got: %s\nwant: %s", formatNodes(tt.netmap.Peers), formatNodes(tt.want))
			}
		})
	}
}

func TestNextPeerExpiry(t *testing.T) {
	n := func(id tailcfg.NodeID, name string, expiry time.Time, mod ...func(*tailcfg.Node)) *tailcfg.Node {
		n := &tailcfg.Node{ID: id, Name: name, KeyExpiry: expiry}
		for _, f := range mod {
			f(n)
		}
		return n
	}

	now := time.Unix(1675725516, 0)

	noExpiry := time.Time{}
	timeInPast := now.Add(-1 * time.Hour)
	timeInFuture := now.Add(1 * time.Hour)
	timeInMoreFuture := now.Add(2 * time.Hour)

	tests := []struct {
		name   string
		netmap *netmap.NetworkMap
		want   time.Time
	}{
		{
			name: "no_expiry",
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", noExpiry),
					n(2, "bar", noExpiry),
				}),
				SelfNode: n(3, "self", noExpiry).View(),
			},
			want: noExpiry,
		},
		{
			name: "future_expiry_from_peer",
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", noExpiry),
					n(2, "bar", timeInFuture),
				}),
				SelfNode: n(3, "self", noExpiry).View(),
			},
			want: timeInFuture,
		},
		{
			name: "future_expiry_from_self",
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", noExpiry),
					n(2, "bar", noExpiry),
				}),
				SelfNode: n(3, "self", timeInFuture).View(),
			},
			want: timeInFuture,
		},
		{
			name: "future_expiry_from_multiple_peers",
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", timeInFuture),
					n(2, "bar", timeInMoreFuture),
				}),
				SelfNode: n(3, "self", noExpiry).View(),
			},
			want: timeInFuture,
		},
		{
			name: "future_expiry_from_peer_and_self",
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", timeInMoreFuture),
				}),
				SelfNode: n(2, "self", timeInFuture).View(),
			},
			want: timeInFuture,
		},
		{
			name: "only_self",
			netmap: &netmap.NetworkMap{
				Peers:    nodeViews([]*tailcfg.Node{}),
				SelfNode: n(1, "self", timeInFuture).View(),
			},
			want: timeInFuture,
		},
		{
			name: "peer_already_expired",
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", timeInPast),
				}),
				SelfNode: n(2, "self", timeInFuture).View(),
			},
			want: timeInFuture,
		},
		{
			name: "self_already_expired",
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", timeInFuture),
				}),
				SelfNode: n(2, "self", timeInPast).View(),
			},
			want: timeInFuture,
		},
		{
			name: "all_nodes_already_expired",
			netmap: &netmap.NetworkMap{
				Peers: nodeViews([]*tailcfg.Node{
					n(1, "foo", timeInPast),
				}),
				SelfNode: n(2, "self", timeInPast).View(),
			},
			want: noExpiry,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bus := eventbustest.NewBus(t)
			em := newExpiryManager(t.Logf, bus)
			em.clock = tstest.NewClock(tstest.ClockOpts{Start: now})
			got := em.nextPeerExpiry(tt.netmap, now)
			if !got.Equal(tt.want) {
				t.Errorf("got %q, want %q", got.Format(time.RFC3339), tt.want.Format(time.RFC3339))
			} else if !got.IsZero() && got.Before(now) {
				t.Errorf("unexpectedly got expiry %q before now %q", got.Format(time.RFC3339), now.Format(time.RFC3339))
			}
		})
	}

	t.Run("ClockSkew", func(t *testing.T) {
		t.Logf("local time:  %q", now.Format(time.RFC3339))
		bus := eventbustest.NewBus(t)
		em := newExpiryManager(t.Logf, bus)
		em.clock = tstest.NewClock(tstest.ClockOpts{Start: now})

		// The local clock is "running fast"; our clock skew is -2h
		em.clockDelta.Store(-2 * time.Hour)
		t.Logf("'real' time: %q", now.Add(-2*time.Hour).Format(time.RFC3339))

		// If we don't adjust for the local time, this would return a
		// time in the past.
		nm := &netmap.NetworkMap{
			Peers: nodeViews([]*tailcfg.Node{
				n(1, "foo", timeInPast),
			}),
		}
		got := em.nextPeerExpiry(nm, now)
		want := now.Add(30 * time.Second)
		if !got.Equal(want) {
			t.Errorf("got %q, want %q", got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	})
}

func formatNodes(nodes []tailcfg.NodeView) string {
	var sb strings.Builder
	for i, n := range nodes {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "(%d, %q", n.ID(), n.Name())

		if online, ok := n.Online().GetOk(); ok {
			fmt.Fprintf(&sb, ", online=%v", online)
		}
		if lastSeen, ok := n.LastSeen().GetOk(); ok {
			fmt.Fprintf(&sb, ", lastSeen=%v", lastSeen.Unix())
		}
		if n.Key() != (key.NodePublic{}) {
			fmt.Fprintf(&sb, ", key=%v", n.Key().String())
		}
		if n.Expired() {
			fmt.Fprintf(&sb, ", expired=true")
		}
		sb.WriteString(")")
	}
	return sb.String()
}
