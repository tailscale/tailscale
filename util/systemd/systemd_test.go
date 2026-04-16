// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package systemd

import "testing"

func TestIsReady(t *testing.T) {
	// Just verify it doesn't panic
	_ = Ready()
}
