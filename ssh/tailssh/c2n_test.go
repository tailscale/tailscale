// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"testing"

	"tailscale.com/util/set"
)

func TestAppendSSHUsernameHint(t *testing.T) {
	tests := []struct {
		name    string
		names   []string
		u       string
		exclude set.Set[string]
		max     int
		want    []string
	}{
		{
			name: "append",
			u:    "alice",
			max:  10,
			want: []string{"alice"},
		},
		{
			name:  "dedupe",
			names: []string{"alice"},
			u:     "alice",
			max:   10,
			want:  []string{"alice"},
		},
		{
			name:    "excluded",
			names:   []string{"alice"},
			u:       "alice",
			exclude: set.SetOf([]string{"alice"}),
			max:     10,
			want:    []string{"alice"},
		},
		{
			name: "service-account-skipped",
			u:    "daemon",
			max:  10,
			want: nil,
		},
		{
			name:  "capped-exactly-at-max",
			names: []string{"alice", "bob", "carol"},
			u:     "dave",
			max:   3,
			want:  []string{"alice", "bob", "carol"},
		},
		{
			name:  "room-for-one-more",
			names: []string{"alice", "bob"},
			u:     "carol",
			max:   3,
			want:  []string{"alice", "bob", "carol"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendSSHUsernameHint(tt.names, tt.u, tt.exclude, tt.max)
			if len(got) != len(tt.want) {
				t.Fatalf("appendSSHUsernameHint(%q) = %q; want %q", tt.u, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("appendSSHUsernameHint(%q) = %q; want %q", tt.u, got, tt.want)
				}
			}
		})
	}
}
