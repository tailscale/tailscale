// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package pool

import (
	"slices"
	"testing"
)

func TestPool(t *testing.T) {
	p := Pool[int]{}

	if got, want := p.Len(), 0; got != want {
		t.Errorf("got initial length %v; want %v", got, want)
	}

	h1 := p.Add(101)
	h2 := p.Add(102)
	h3 := p.Add(103)
	h4 := p.Add(104)

	if got, want := p.Len(), 4; got != want {
		t.Errorf("got length %v; want %v", got, want)
	}

	tests := []struct {
		h    Handle[int]
		want int
	}{
		{h1, 101},
		{h2, 102},
		{h3, 103},
		{h4, 104},
	}
	for i, test := range tests {
		got, ok := p.Peek(test.h)
		if !ok {
			t.Errorf("test[%d]: did not find item", i)
			continue
		}
		if got != test.want {
			t.Errorf("test[%d]: got %v; want %v", i, got, test.want)
		}
	}

	if deleted := p.Delete(h2); !deleted {
		t.Errorf("h2 not deleted")
	}
	if deleted := p.Delete(h2); deleted {
		t.Errorf("h2 should not be deleted twice")
	}
	if got, want := p.Len(), 3; got != want {
		t.Errorf("got length %v; want %v", got, want)
	}
	if _, ok := p.Peek(h2); ok {
		t.Errorf("h2 still in pool")
	}

	// Remove an item by handle
	got, ok := p.Take(h4)
	if !ok {
		t.Errorf("h4 not found")
	}
	if got != 104 {
		t.Errorf("got %v; want 104", got)
	}

	// Take doesn't work on previously-taken or deleted items.
	if _, ok := p.Take(h4); ok {
		t.Errorf("h4 should not be taken twice")
	}
	if _, ok := p.Take(h2); ok {
		t.Errorf("h2 should not be taken after delete")
	}

	// Remove all items and return them
	items := p.AppendTakeAll(nil)
	want := []int{101, 103}
	if !slices.Equal(items, want) {
		t.Errorf("got items %v; want %v", items, want)
	}
	if got := p.Len(); got != 0 {
		t.Errorf("got length %v; want 0", got)
	}

	// Insert and then clear should result in no items.
	p.Add(105)
	p.Clear()
	if got := p.Len(); got != 0 {
		t.Errorf("got length %v; want 0", got)
	}
}

func TestTakeRandom(t *testing.T) {
	p := Pool[int]{}
	for i := 0; i < 10; i++ {
		p.Add(i + 100)
	}

	seen := make(map[int]bool)
	for i := 0; i < 10; i++ {
		item, ok := p.TakeRandom()
		if !ok {
			t.Errorf("unexpected empty pool")
			break
		}
		if seen[item] {
			t.Errorf("got duplicate item %v", item)
		}
		seen[item] = true
	}

	// Verify that the pool is empty
	if _, ok := p.TakeRandom(); ok {
		t.Errorf("expected empty pool")
	}

	for i := 0; i < 10; i++ {
		want := 100 + i
		if !seen[want] {
			t.Errorf("item %v not seen", want)
		}
	}

	if t.Failed() {
		t.Logf("seen: %+v", seen)
	}
}

func BenchmarkPool_AddDelete(b *testing.B) {
	b.Run("impl=Pool", func(b *testing.B) {
		p := Pool[int]{}

		// Warm up/force an initial allocation
		h := p.Add(0)
		p.Delete(h)

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			h := p.Add(i)
			p.Delete(h)
		}
	})
	b.Run("impl=map", func(b *testing.B) {
		p := make(map[int]bool)

		// Force initial allocation
		p[0] = true
		delete(p, 0)

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			p[i] = true
			delete(p, i)
		}
	})
}

func BenchmarkPool_TakeRandom(b *testing.B) {
	b.Run("impl=Pool", func(b *testing.B) {
		p := Pool[int]{}

		// Insert the number of items we'll be taking, then reset the timer.
		for i := 0; i < b.N; i++ {
			p.Add(i)
		}
		b.ResetTimer()

		// Now benchmark taking all the items.
		for i := 0; i < b.N; i++ {
			p.TakeRandom()
		}

		if p.Len() != 0 {
			b.Errorf("pool not empty")
		}
	})
	b.Run("impl=map", func(b *testing.B) {
		p := make(map[int]bool)

		// Insert the number of items we'll be taking, then reset the timer.
		for i := 0; i < b.N; i++ {
			p[i] = true
		}
		b.ResetTimer()

		// Now benchmark taking all the items.
		for i := 0; i < b.N; i++ {
			// Taking a random item is simulated by a single map iteration.
			for k := range p {
				delete(p, k) // "take" the item by removing it
				break
			}
		}

		if len(p) != 0 {
			b.Errorf("map not empty")
		}
	})
}
