// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package drive

import (
	"encoding/json"
	"testing"
)

func TestPermissions(t *testing.T) {
	tests := []struct {
		perms []grant
		share string
		want  Permission
	}{
		{[]grant{
			{Shares: []string{"*"}, Access: "ro"},
			{Shares: []string{"a"}, Access: "rw"},
		},
			"a",
			PermissionReadWrite,
		},
		{[]grant{
			{Shares: []string{"*"}, Access: "ro"},
			{Shares: []string{"a"}, Access: "rw"},
		},
			"b",
			PermissionReadOnly,
		},
		{[]grant{
			{Shares: []string{"a"}, Access: "rw"},
		},
			"c",
			PermissionNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.share, func(t *testing.T) {
			var rawPerms [][]byte
			for _, perm := range tt.perms {
				b, err := json.Marshal(perm)
				if err != nil {
					t.Fatal(err)
				}
				rawPerms = append(rawPerms, b)
			}

			p, err := ParsePermissions(rawPerms)
			if err != nil {
				t.Fatal(err)
			}

			got := p.For(tt.share)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
