// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"fmt"
	"testing"
)

func TestShouldUseLogin(t *testing.T) {
	tests := []struct {
		goos    string
		hasTTY  bool
		isShell bool
		want    bool
	}{
		// darwin: login can exec, so only non-TTY exec bails (#18256).
		{darwin, true, true, true},
		{darwin, true, false, true},
		{darwin, false, true, true},
		{darwin, false, false, false},

		// linux: login can't exec commands and needs a TTY.
		{linux, true, true, true},
		{linux, true, false, false},
		{linux, false, true, false},
		{linux, false, false, false},

		// freebsd: same as linux.
		{freebsd, true, true, true},
		{freebsd, true, false, false},
		{freebsd, false, true, false},
		{freebsd, false, false, false},

		// openbsd: same as linux.
		{openbsd, true, true, true},
		{openbsd, true, false, false},
		{openbsd, false, true, false},
		{openbsd, false, false, false},
	}
	for _, tt := range tests {
		name := fmt.Sprintf("%s/tty=%v/shell=%v", tt.goos, tt.hasTTY, tt.isShell)
		t.Run(name, func(t *testing.T) {
			got, reason := shouldUseLogin(tt.goos, tt.hasTTY, tt.isShell)
			if got != tt.want {
				t.Errorf("shouldUseLogin(%q, hasTTY=%v, isShell=%v) = %v (%q); want %v",
					tt.goos, tt.hasTTY, tt.isShell, got, reason, tt.want)
			}
			if got && reason != "" {
				t.Errorf("use=true should have empty reason, got %q", reason)
			}
			if !got && reason == "" {
				t.Errorf("use=false should have non-empty reason")
			}
		})
	}
}
