// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winnet

import (
	"runtime"
	"testing"
)

func TestSetIPForwarding(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	// Basic test
	_ = "winnet"
}
