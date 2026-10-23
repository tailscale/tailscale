// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestPeerHiddenInGUI(t *testing.T) {
	self := (&tailcfg.Node{
		ID:   1,
		User: 10,
	}).View()
	sameUser := (&tailcfg.Node{
		ID:   2,
		User: 10,
	}).View()
	otherUser := (&tailcfg.Node{
		ID:   3,
		User: 20,
	}).View()
	tagged := (&tailcfg.Node{
		ID:   4,
		User: 20,
		Tags: []string{"tag:server"},
	}).View()
	sharedByCurrentUser := (&tailcfg.Node{
		ID:     5,
		User:   20,
		Sharer: 10,
	}).View()

	tests := []struct {
		name   string
		peer   tailcfg.NodeView
		hidden hiddenNetworkDevices
		want   bool
	}{
		{
			name: "no-policy/same-user",
			peer: sameUser,
		},
		{
			name: "no-policy/other-user",
			peer: otherUser,
		},
		{
			name: "no-policy/tagged",
			peer: tagged,
		},
		{
			name: "current-user/self-stays-visible",
			peer: self,
			hidden: hiddenNetworkDevices{
				currentUser: true,
			},
		},
		{
			name: "current-user/same-user",
			peer: sameUser,
			hidden: hiddenNetworkDevices{
				currentUser: true,
			},
			want: true,
		},
		{
			name: "current-user/shared-by-current-user",
			peer: sharedByCurrentUser,
			hidden: hiddenNetworkDevices{
				currentUser: true,
			},
			want: true,
		},
		{
			name: "current-user/other-user",
			peer: otherUser,
			hidden: hiddenNetworkDevices{
				currentUser: true,
			},
		},
		{
			name: "other-users/other-user",
			peer: otherUser,
			hidden: hiddenNetworkDevices{
				otherUsers: true,
			},
			want: true,
		},
		{
			name: "other-users/tagged-is-separate",
			peer: tagged,
			hidden: hiddenNetworkDevices{
				otherUsers: true,
			},
		},
		{
			name: "tagged-devices/tagged",
			peer: tagged,
			hidden: hiddenNetworkDevices{
				taggedDevices: true,
			},
			want: true,
		},
		{
			name: "tagged-devices/other-user",
			peer: otherUser,
			hidden: hiddenNetworkDevices{
				taggedDevices: true,
			},
		},
		{
			name: "all/same-user",
			peer: sameUser,
			hidden: hiddenNetworkDevices{
				currentUser:   true,
				otherUsers:    true,
				taggedDevices: true,
			},
			want: true,
		},
		{
			name: "all/other-user",
			peer: otherUser,
			hidden: hiddenNetworkDevices{
				currentUser:   true,
				otherUsers:    true,
				taggedDevices: true,
			},
			want: true,
		},
		{
			name: "all/tagged",
			peer: tagged,
			hidden: hiddenNetworkDevices{
				currentUser:   true,
				otherUsers:    true,
				taggedDevices: true,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := peerHiddenInGUI(tt.peer, self, tt.hidden); got != tt.want {
				t.Fatalf("peerHiddenInGUI() = %v, want %v", got, tt.want)
			}
		})
	}
}
