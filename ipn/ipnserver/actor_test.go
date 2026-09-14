// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnserver

import (
	"os/user"
	"slices"
	"testing"
)

func TestSudoCheckCmd(t *testing.T) {
	for _, tt := range []struct {
		name     string
		username string
		fullName string
	}{
		{"issue21204", "ufuk", "Ufuk Ustali"},
		{"ordinary", "alice", "Alice Example"},
		{"empty_display_name", "alice", ""},
		{"matching_names", "alice", "alice"},
		{"spaces", "alice example", "Alice Example"},
		{"domain", `DOMAIN\alice`, "Alice Example"},
		{"email", "alice@example.com", "Alice Example"},
		{"unicode", "alïce", "Alice Example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := sudoCheckCmd(t.Context(), &user.User{
				Username: tt.username,
				Name:     tt.fullName,
			})
			// Inspect argv without running sudo or depending on the host's accounts.
			want := []string{"sudo", "--other-user=" + tt.username, "--list", "tailscale"}
			if !slices.Equal(cmd.Args, want) {
				t.Fatalf("sudo argv = %q, want %q", cmd.Args, want)
			}
		})
	}
}
