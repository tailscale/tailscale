// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ringlog

import (
	"reflect"
	"testing"
)

func TestRingLog(t *testing.T) {
	const numItems = 10
	rb := New[int](numItems)

	for i := range numItems - 1 {
		rb.Add(i)
	}

	t.Run("NotFull", func(t *testing.T) {
		if ll := rb.Len(); ll != numItems-1 {
			t.Fatalf("got len %d; want %d", ll, numItems-1)
		}
		all := rb.GetAll()
		want := []int{0, 1, 2, 3, 4, 5, 6, 7, 8}
		if !reflect.DeepEqual(all, want) {
			t.Fatalf("items mismatch\ngot: %v\nwant %v", all, want)
		}
	})

	t.Run("Full", func(t *testing.T) {
		// Append items to evict something
		rb.Add(98)
		rb.Add(99)

		if ll := rb.Len(); ll != numItems {
			t.Fatalf("got len %d; want %d", ll, numItems)
		}
		all := rb.GetAll()
		want := []int{1, 2, 3, 4, 5, 6, 7, 8, 98, 99}
		if !reflect.DeepEqual(all, want) {
			t.Fatalf("items mismatch\ngot: %v\nwant %v", all, want)
		}
	})

	t.Run("Clear", func(t *testing.T) {
		rb.Clear()
		if ll := rb.Len(); ll != 0 {
			t.Fatalf("got len %d; want 0", ll)
		}
		all := rb.GetAll()
		if len(all) != 0 {
			t.Fatalf("got non-empty list; want empty")
		}
	})
}

// TestNil verifies that every method tolerates a nil *RingLog, which is how
// callers that opt out of logging represent a disabled log. For example,
// magicsock leaves endpoint.debugUpdates nil on iOS and Android to save memory.
func TestNil(t *testing.T) {
	var rb *RingLog[int]
	rb.Add(1)
	if got := rb.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0", got)
	}
	if got := rb.GetAll(); got != nil {
		t.Errorf("GetAll() = %v, want nil", got)
	}
	rb.Clear()
}
