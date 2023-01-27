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
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
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
		want        []*tailcfg.Node
	}{
		{
			name:        "no_expiry",
			controlTime: &now,
			netmap: &netmap.NetworkMap{
				Peers: []*tailcfg.Node{
					n(1, "foo", timeInFuture),
					n(2, "bar", timeInFuture),
				},
			},
			want: []*tailcfg.Node{
				n(1, "foo", timeInFuture),
				n(2, "bar", timeInFuture),
			},
		},
		{
			name:        "expiry",
			controlTime: &now,
			netmap: &netmap.NetworkMap{
				Peers: []*tailcfg.Node{
					n(1, "foo", timeInFuture),
					n(2, "bar", timeInPast),
				},
			},
			want: []*tailcfg.Node{
				n(1, "foo", timeInFuture),
				n(2, "bar", timeInPast, func(n *tailcfg.Node) {
					n.Expired = true
					n.Key = expiredKey
				}),
			},
		},
		{
			name: "bad_ControlTime",
			// controlTime here is intentionally before our hardcoded epoch
			controlTime: &timeBeforeEpoch,

			netmap: &netmap.NetworkMap{
				Peers: []*tailcfg.Node{
					n(1, "foo", timeInFuture),
					n(2, "bar", timeBeforeEpoch.Add(-1*time.Hour)), // before ControlTime
				},
			},
			want: []*tailcfg.Node{
				n(1, "foo", timeInFuture),
				n(2, "bar", timeBeforeEpoch.Add(-1*time.Hour)), // should have expired, but ControlTime is before epoch
			},
		},
		{
			name:        "tagged_node",
			controlTime: &now,
			netmap: &netmap.NetworkMap{
				Peers: []*tailcfg.Node{
					n(1, "foo", timeInFuture),
					n(2, "bar", time.Time{}), // tagged node; zero expiry
				},
			},
			want: []*tailcfg.Node{
				n(1, "foo", timeInFuture),
				n(2, "bar", time.Time{}), // not expired
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			em := newExpiryManager(t.Logf)
			em.timeNow = func() time.Time { return now }

			if tt.controlTime != nil {
				em.onControlTime(*tt.controlTime)
			}
			em.flagExpiredPeers(tt.netmap)
			if !reflect.DeepEqual(tt.netmap.Peers, tt.want) {
				t.Errorf("wrong results\n got: %s\nwant: %s", formatNodes(tt.netmap.Peers), formatNodes(tt.want))
			}
		})
	}
}

func formatNodes(nodes []*tailcfg.Node) string {
	var sb strings.Builder
	for i, n := range nodes {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "(%d, %q", n.ID, n.Name)

		if n.Online != nil {
			fmt.Fprintf(&sb, ", online=%v", *n.Online)
		}
		if n.LastSeen != nil {
			fmt.Fprintf(&sb, ", lastSeen=%v", n.LastSeen.Unix())
		}
		if n.Key != (key.NodePublic{}) {
			fmt.Fprintf(&sb, ", key=%v", n.Key.String())
		}
		if n.Expired {
			fmt.Fprintf(&sb, ", expired=true")
		}
		sb.WriteString(")")
	}
	return sb.String()
}
