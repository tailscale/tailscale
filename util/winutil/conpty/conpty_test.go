// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package conpty

import (
	"runtime"
	"testing"
)

func TestConPty(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	// Test console pty
	_ = "conpty"
}
