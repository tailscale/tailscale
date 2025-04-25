// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mapx

import (
	"fmt"
	"slices"
	"testing"
)

func TestOrderedMap(t *testing.T) {
	// Test the OrderedMap type and its methods.
	var m OrderedMap[string, int]
	m.Set("d", 4)
	m.Set("a", 1)
	m.Set("b", 1)
	m.Set("b", 2)
	m.Set("c", 3)
	m.Delete("d")
	m.Delete("e")

	want := map[string]int{
		"a": 1,
		"b": 2,
		"c": 3,
		"d": 0,
	}
	for k, v := range want {
		if m.Get(k) != v {
			t.Errorf("Get(%q) = %d, want %d", k, m.Get(k), v)
			continue
		}
		got, ok := m.GetOk(k)
		if got != v {
			t.Errorf("GetOk(%q) = %d, want %d", k, got, v)
		}
		if ok != m.Contains(k) {
			t.Errorf("GetOk and Contains don't agree for %q", k)
		}
	}

	if got, want := slices.Collect(m.Keys()), []string{"a", "b", "c"}; !slices.Equal(got, want) {
		t.Errorf("Keys() = %q, want %q", got, want)
	}
	if got, want := slices.Collect(m.Values()), []int{1, 2, 3}; !slices.Equal(got, want) {
		t.Errorf("Values() = %v, want %v", got, want)
	}
	var allGot []string
	for k, v := range m.All() {
		allGot = append(allGot, fmt.Sprintf("%s:%d", k, v))
	}
	if got, want := allGot, []string{"a:1", "b:2", "c:3"}; !slices.Equal(got, want) {
		t.Errorf("All() = %q, want %q", got, want)
	}
}
