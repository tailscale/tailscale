// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package guivisibility

import (
	"testing"

	"tailscale.com/tailcfg"
)

func TestVisibilityFilter(t *testing.T) {
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
		filter visibilityFilter
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
			name:   "current-user/self-stays-visible",
			peer:   self,
			filter: visibilityFilter{currentUser: true},
		},
		{
			name:   "current-user/same-user",
			peer:   sameUser,
			filter: visibilityFilter{currentUser: true},
			want:   true,
		},
		{
			name:   "current-user/shared-by-current-user",
			peer:   sharedByCurrentUser,
			filter: visibilityFilter{currentUser: true},
			want:   true,
		},
		{
			name:   "current-user/other-user",
			peer:   otherUser,
			filter: visibilityFilter{currentUser: true},
		},
		{
			name:   "other-users/other-user",
			peer:   otherUser,
			filter: visibilityFilter{otherUsers: true},
			want:   true,
		},
		{
			name:   "other-users/tagged-is-separate",
			peer:   tagged,
			filter: visibilityFilter{otherUsers: true},
		},
		{
			name:   "tagged-devices/tagged",
			peer:   tagged,
			filter: visibilityFilter{taggedDevices: true},
			want:   true,
		},
		{
			name:   "tagged-devices/other-user",
			peer:   otherUser,
			filter: visibilityFilter{taggedDevices: true},
		},
		{
			name:   "all/same-user",
			peer:   sameUser,
			filter: visibilityFilter{true, true, true},
			want:   true,
		},
		{
			name:   "all/other-user",
			peer:   otherUser,
			filter: visibilityFilter{true, true, true},
			want:   true,
		},
		{
			name:   "all/tagged",
			peer:   tagged,
			filter: visibilityFilter{true, true, true},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.Hide(tt.peer, self); got != tt.want {
				t.Fatalf("Hide() = %v, want %v", got, tt.want)
			}
		})
	}
}
