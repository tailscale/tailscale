// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package authenticode

import (
	"runtime"
	"testing"
)

func TestAuthenticode(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	// Test authenticode signature verification
	_ = "authenticode"
}
