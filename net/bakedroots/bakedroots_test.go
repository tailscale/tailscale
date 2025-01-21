// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package bakedroots

import "testing"

func TestBakedInRoots(t *testing.T) {
	ResetForTest(t, nil)
	p := Get()
	got := p.Subjects()
	if len(got) != 1 {
		t.Errorf("subjects = %v; want 1", len(got))
	}
}
