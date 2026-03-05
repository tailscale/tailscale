// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package s4u

import (
	"runtime"
	"testing"
)

func TestS4U(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	// Test S4U (Service-for-User)
	_ = "s4u"
}
