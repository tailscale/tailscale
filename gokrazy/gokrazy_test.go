// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package gokrazy

import "testing"

func TestIsGokrazy(t *testing.T) {
	_ = IsGokrazy()
	// Just verify it doesn't panic
}
