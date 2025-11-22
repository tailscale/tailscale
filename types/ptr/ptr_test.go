// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ptr

import "testing"

func TestTo(t *testing.T) {
	i := 42
	p := To(i)
	if p == nil {
		t.Fatal("To() returned nil")
	}
	if *p != 42 {
		t.Errorf("*To(42) = %d, want 42", *p)
	}
}
