// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package circularqueue

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFIFO(t *testing.T) {
	var evicted []int
	q := NewFIFO(3, func(item int) {
		evicted = append(evicted, item)
	})

	assertPop := func(idx int, want int) {
		t.Helper()
		got := q.Pop(idx)
		var _want *int
		if want >= 0 {
			_want = &want
		}
		if diff := cmp.Diff(got, _want); diff != "" {
			t.Fatalf("unexpected item (-got +want):\n%s", diff)
		}
	}

	q.Push(1)
	q.Push(2)
	q.Push(3)
	assertPop(3, -1)
	assertPop(Head, 1)
	assertPop(2, 3) // Should evict 2
	assertPop(2, -1)

	q.Push(4)
	q.Push(5)
	q.Push(6)
	assertPop(5, 6) // Should evict 4 and 5

	if diff := cmp.Diff(evicted, []int{2, 4, 5}); diff != "" {
		t.Fatalf("unexpected evicted (-got +want):\n%s", diff)
	}

}
