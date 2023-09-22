// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package tstun

import (
	"os"
	"testing"
)

func TestDefaultMTU(t *testing.T) {
	orig := os.Getenv("TS_DEBUG_MTU")
	defer os.Setenv("TS_DEBUG_MTU", orig)

	os.Setenv("TS_DEBUG_MTU", "")
	if DefaultMTU() != 1280 {
		t.Errorf("DefaultMTU() = %d, want 1280", DefaultMTU())
	}

	os.Setenv("TS_DEBUG_MTU", "9000")
	if DefaultMTU() != 9000 {
		t.Errorf("DefaultMTU() = %d, want 9000", DefaultMTU())
	}

	os.Setenv("TS_DEBUG_MTU", "123456789")
	if DefaultMTU() != maxMTU {
		t.Errorf("DefaultMTU() = %d, want %d", DefaultMTU(), maxMTU)
	}
}
