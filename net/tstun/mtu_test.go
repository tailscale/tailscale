// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package tstun

import (
	"os"
	"testing"
)

func TestTunMTU(t *testing.T) {
	orig := os.Getenv("TS_DEBUG_MTU")
	defer os.Setenv("TS_DEBUG_MTU", orig)

	os.Setenv("TS_DEBUG_MTU", "")
	if TunMTU() != 1280 {
		t.Errorf("TunMTU() = %d, want 1280", TunMTU())
	}

	os.Setenv("TS_DEBUG_MTU", "9000")
	if TunMTU() != 9000 {
		t.Errorf("TunMTU() = %d, want 9000", TunMTU())
	}

	os.Setenv("TS_DEBUG_MTU", "123456789")
	if TunMTU() != maxMTU {
		t.Errorf("TunMTU() = %d, want %d", TunMTU(), maxMTU)
	}
}
