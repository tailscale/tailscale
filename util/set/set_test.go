// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package set

import "testing"

func TestSet(t *testing.T) {
	s := Set[int]{}
	s.Add(1)
	s.Add(2)
	if !s.Contains(1) {
		t.Error("missing 1")
	}
	if !s.Contains(2) {
		t.Error("missing 2")
	}
	if s.Contains(3) {
		t.Error("shouldn't have 3")
	}
	if s.Len() != 2 {
		t.Errorf("wrong len %d; want 2", s.Len())
	}
}
