// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package bools

import "testing"

func TestInt(t *testing.T) {
	if got := Int(true); got != 1 {
		t.Errorf("Int(true) = %v, want 1", got)
	}
	if got := Int(false); got != 0 {
		t.Errorf("Int(false) = %v, want 0", got)
	}
}

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

func TestIfElse(t *testing.T) {
	if got := IfElse(true, 0, 1); got != 0 {
		t.Errorf("IfElse(true, 0, 1) = %v, want 0", got)
	}
	if got := IfElse(false, 0, 1); got != 1 {
		t.Errorf("IfElse(false, 0, 1) = %v, want 1", got)
	}
}
