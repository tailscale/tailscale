// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck_test

import (
	"testing"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/routecheck"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

func TestIsConn25Connector(t *testing.T) {
	for _, tc := range []struct {
		name string
		node tailcfg.NodeView
		want bool
	}{
		{
			name: "plain-peer",
			node: makeNode(1, withName("peer1")),
			want: false,
		},
		{
			name: "connector",
			node: makeNode(2, withName("connector2"), withConn25Connector("example")),
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := routecheck.IsConn25Connector(tc.node); got != tc.want {
				t.Errorf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestPeerStatusIsConn25Connector(t *testing.T) {
	for _, tc := range []struct {
		name string
		ps   *ipnstate.PeerStatus
		want bool
	}{
		{
			name: "nil",
			ps:   nil,
			want: false,
		},
		{
			name: "plain-peer",
			ps:   &ipnstate.PeerStatus{},
			want: false,
		},
		{
			name: "connector",
			ps: &ipnstate.PeerStatus{
				CapMap: tailcfg.NodeCapMap{
					nodecap.Conn25Connector: nil,
				},
			},
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := routecheck.PeerStatusIsConn25Connector(tc.ps); got != tc.want {
				t.Errorf("got %t, want %t", got, tc.want)
			}
		})
	}
}
