// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package mapx

import (
	"fmt"
	"testing"
)

func TestRepopulateNonzero(t *testing.T) {
	var m map[string]int

	// First call: nil map gets initialized and populated.
	RepopulateNonzero(&m, func() {
		m["a"] = 1
		m["b"] = 2
	})
	if got, want := len(m), 2; got != want {
		t.Fatalf("len = %d, want %d", got, want)
	}
	if m["a"] != 1 || m["b"] != 2 {
		t.Fatalf("got %v, want map[a:1 b:2]", m)
	}

	// Second call: "b" is no longer populated, so it should be removed.
	RepopulateNonzero(&m, func() {
		m["a"] = 3
		m["c"] = 4
	})
	if got, want := len(m), 2; got != want {
		t.Fatalf("len = %d, want %d", got, want)
	}
	if m["a"] != 3 || m["c"] != 4 {
		t.Fatalf("got %v, want map[a:3 c:4]", m)
	}
	if _, ok := m["b"]; ok {
		t.Fatal("key 'b' should have been removed")
	}

	// Populating nothing should clear the map.
	RepopulateNonzero(&m, func() {})
	if got := len(m); got != 0 {
		t.Fatalf("len = %d after empty populate, want 0", got)
	}
}

func BenchmarkRepopulateNonzero(b *testing.B) {
	for _, size := range []int{5, 100, 100_000} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.Run("RepopulateNonzero", func(b *testing.B) {
				var m map[string]int
				keys := makeKeys(size)
				// Seed the map so the first iteration isn't special.
				RepopulateNonzero(&m, func() {
					for i, k := range keys {
						m[k] = i + 1
					}
				})
				b.ResetTimer()
				for range b.N {
					RepopulateNonzero(&m, func() {
						for i, k := range keys {
							m[k] = i + 1
						}
					})
				}
			})
			b.Run("clear", func(b *testing.B) {
				m := make(map[string]int, size)
				keys := makeKeys(size)
				for i, k := range keys {
					m[k] = i + 1
				}
				b.ResetTimer()
				for range b.N {
					m = make(map[string]int, size)
					for i, k := range keys {
						m[k] = i + 1
					}
				}
			})
		})
	}
}

func makeKeys(n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("key-%d", i)
	}
	return keys
}
