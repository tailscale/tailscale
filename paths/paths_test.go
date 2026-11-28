// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package paths

import (
	"slices"
	"testing"
)

func TestUnixTailscaledSocket(t *testing.T) {
	tests := []struct {
		name string
		dirs []string
		want string
	}{
		{"var-run-and-run", []string{"/var/run", "/run"}, "/var/run/tailscale/tailscaled.sock"},
		{"var-run-only", []string{"/var/run"}, "/var/run/tailscale/tailscaled.sock"},
		// No /var/run compatibility symlink (#18203). tailscaled.service
		// puts the socket under /run/tailscale, so the CLI must look there
		// too instead of in the current directory.
		{"run-only", []string{"/run"}, "/run/tailscale/tailscaled.sock"},
		{"neither", nil, "tailscaled.sock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isDir := func(name string) bool { return slices.Contains(tt.dirs, name) }
			if got := unixTailscaledSocket(isDir); got != tt.want {
				t.Errorf("unixTailscaledSocket() = %q, want %q", got, tt.want)
			}
		})
	}
}
