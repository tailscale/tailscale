// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package bools

import "testing"

func TestCompare(t *testing.T) {
	if got := Compare(false, false); got != 0 {
		t.Errorf("Compare(false, false) = %v, want 0", got)
	}
	if got := Compare(false, true); got != -1 {
		t.Errorf("Compare(false, true) = %v, want -1", got)
	}
	if got := Compare(true, false); got != +1 {
		t.Errorf("Compare(true, false) = %v, want +1", got)
	}
	if got := Compare(true, true); got != 0 {
		t.Errorf("Compare(true, true) = %v, want 0", got)
	}
}
