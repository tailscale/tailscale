// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import "testing"

func TestShardedMap(t *testing.T) {
	m := NewShardedMap[int, string](16, func(i int) int { return i % 16 })

	if m.Contains(1) {
		t.Errorf("got contains; want !contains")
	}
	if !m.Set(1, "one") {
		t.Errorf("got !set; want set")
	}
	if m.Set(1, "one") {
		t.Errorf("got set; want !set")
	}
	if !m.Contains(1) {
		t.Errorf("got !contains; want contains")
	}
	if g, w := m.Get(1), "one"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	if _, ok := m.GetOk(1); !ok {
		t.Errorf("got ok; want !ok")
	}
	if _, ok := m.GetOk(2); ok {
		t.Errorf("got ok; want !ok")
	}
	if g, w := m.Len(), 1; g != w {
		t.Errorf("got Len %v; want %v", g, w)
	}
	if m.Delete(2) {
		t.Errorf("got deleted; want !deleted")
	}
	if !m.Delete(1) {
		t.Errorf("got !deleted; want deleted")
	}
	if g, w := m.Len(), 0; g != w {
		t.Errorf("got Len %v; want %v", g, w)
	}
}
