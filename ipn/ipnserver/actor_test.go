// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnserver

import (
	"slices"
	"testing"
)

func TestSudoCheckCmd(t *testing.T) {
	cmd := sudoCheckCmd(t.Context(), "ufuk")
	// Inspect argv without running sudo or depending on the host's accounts.
	want := []string{"sudo", "--other-user=ufuk", "--list", "tailscale"}
	if !slices.Equal(cmd.Args, want) {
		t.Fatalf("sudo argv = %q, want %q", cmd.Args, want)
	}
}
