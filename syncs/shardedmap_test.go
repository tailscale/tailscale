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

	// Mutation adding an entry.
	if v := m.Mutate(1, func(was string, ok bool) (string, bool) {
		if ok {
			t.Fatal("was okay")
		}
		return "ONE", true
	}); v != 1 {
		t.Errorf("Mutate = %v; want 1", v)
	}
	if g, w := m.Get(1), "ONE"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	// Mutation changing an entry.
	if v := m.Mutate(1, func(was string, ok bool) (string, bool) {
		if !ok {
			t.Fatal("wasn't okay")
		}
		return was + "-" + was, true
	}); v != 0 {
		t.Errorf("Mutate = %v; want 0", v)
	}
	if g, w := m.Get(1), "ONE-ONE"; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
	// Mutation removing an entry.
	if v := m.Mutate(1, func(was string, ok bool) (string, bool) {
		if !ok {
			t.Fatal("wasn't okay")
		}
		return "", false
	}); v != -1 {
		t.Errorf("Mutate = %v; want -1", v)
	}
	if g, w := m.Get(1), ""; g != w {
		t.Errorf("got %q; want %q", g, w)
	}
}
