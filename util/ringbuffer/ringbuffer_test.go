// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ringbuffer

import (
	"sync"
	"testing"
)

func TestNew(t *testing.T) {
	rb := New[int](5)
	if rb == nil {
		t.Fatal("New returned nil")
	}
	if rb.Cap() != 5 {
		t.Errorf("Cap() = %d, want 5", rb.Cap())
	}
	if rb.Len() != 0 {
		t.Errorf("Len() = %d, want 0", rb.Len())
	}
}

func TestNewPanicsOnZeroCapacity(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("New(0) did not panic")
		}
	}()
	New[int](0)
}

func TestNewPanicsOnNegativeCapacity(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("New(-1) did not panic")
		}
	}()
	New[int](-1)
}

func TestPushSingleItem(t *testing.T) {
	rb := New[int](3)

	displaced := rb.Push(42)
	if displaced {
		t.Error("Push(42) displaced item when buffer was empty")
	}

	if rb.Len() != 1 {
		t.Errorf("Len() = %d, want 1", rb.Len())
	}
}

func TestPushMultipleItems(t *testing.T) {
	rb := New[int](3)

	for i := range 3 {
		displaced := rb.Push(i + 1)
		if displaced {
			t.Errorf("Push(%d) displaced item when buffer wasn't full", i+1)
		}
	}

	if rb.Len() != 3 {
		t.Errorf("Len() = %d, want 3", rb.Len())
	}
	if rb.Len() != rb.Cap() {
		t.Error("Buffer should be at capacity")
	}
}

func TestPushDisplacement(t *testing.T) {
	rb := New[int](3)

	for i := range 3 {
		rb.Push(i + 1)
	}

	displaced := rb.Push(4)
	if !displaced {
		t.Error("Push(4) did not report displacement when buffer was full")
	}

	if rb.Len() != 3 {
		t.Errorf("Len() = %d, want 3", rb.Len())
	}

	items := rb.Drain()
	expected := []int{2, 3, 4}
	if len(items) != len(expected) {
		t.Fatalf("Drain() returned %d items, want %d", len(items), len(expected))
	}
	for i, want := range expected {
		if items[i] != want {
			t.Errorf("Drain()[%d] = %d, want %d", i, items[i], want)
		}
	}

	if rb.Len() != 0 {
		t.Errorf("Len() = %d after Drain(), want 0", rb.Len())
	}
}

func TestPop(t *testing.T) {
	rb := New[int](3)

	item, ok := rb.Pop()
	if ok {
		t.Error("Pop() returned ok=true for empty buffer")
	}
	if item != 0 {
		t.Errorf("Pop() returned %d for empty buffer, want 0", item)
	}

	rb.Push(1)
	rb.Push(2)
	rb.Push(3)

	for i := range 3 {
		item, ok := rb.Pop()
		if !ok {
			t.Errorf("Pop() returned ok=false, want true")
		}
		if item != i+1 {
			t.Errorf("Pop() = %d, want %d", item, i+1)
		}
	}

	if rb.Len() != 0 {
		t.Error("Len() != 0 after popping all items")
	}
}

func TestClear(t *testing.T) {
	rb := New[int](3)

	rb.Push(1)
	rb.Push(2)
	rb.Push(3)

	rb.Clear()

	if rb.Len() != 0 {
		t.Errorf("Len() = %d after Clear(), want 0", rb.Len())
	}

	items := rb.Drain()
	if items != nil {
		t.Errorf("Drain() = %v after Clear(), want nil", items)
	}
}

func TestDrain(t *testing.T) {
	rb := New[int](5)

	items := rb.Drain()
	if items != nil {
		t.Errorf("Drain() = %v for empty buffer, want nil", items)
	}

	rb.Push(1)
	rb.Push(2)
	rb.Push(3)

	items = rb.Drain()
	expected := []int{1, 2, 3}
	if len(items) != len(expected) {
		t.Fatalf("Drain() returned %d items, want %d", len(items), len(expected))
	}
	for i, want := range expected {
		if items[i] != want {
			t.Errorf("Drain()[%d] = %d, want %d", i, items[i], want)
		}
	}

	if rb.Len() != 0 {
		t.Errorf("Len() = %d after Drain(), want 0", rb.Len())
	}

	rb.Push(1)
	rb.Push(2)
	rb.Push(3)
	rb.Push(4)
	rb.Push(5)
	rb.Push(6) // displace 1

	items = rb.Drain()
	expected = []int{2, 3, 4, 5, 6}
	if len(items) != len(expected) {
		t.Fatalf("Drain() returned %d items, want %d", len(items), len(expected))
	}
	for i, want := range expected {
		if items[i] != want {
			t.Errorf("Drain()[%d] = %d, want %d", i, items[i], want)
		}
	}

	if rb.Len() != 0 {
		t.Errorf("Len() = %d after second Drain(), want 0", rb.Len())
	}
}

func TestNilRingBuffer(t *testing.T) {
	var rb *RingBuffer[int]

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Push on nil RingBuffer did not panic")
			}
		}()
		rb.Push(1)
	}()

	if item, ok := rb.Pop(); ok || item != 0 {
		t.Errorf("Pop() = (%d, %t), want (0, false)", item, ok)
	}

	if rb.Len() != 0 {
		t.Errorf("Len() = %d, want 0", rb.Len())
	}

	if rb.Cap() != 0 {
		t.Errorf("Cap() = %d, want 0", rb.Cap())
	}

	rb.Clear()

	items := rb.Drain()
	if items != nil {
		t.Errorf("Drain() = %v, want nil", items)
	}
}

func TestConcurrentAccess(t *testing.T) {
	rb := New[int](100)
	var wg sync.WaitGroup

	for i := range 10 {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			for j := range 100 {
				rb.Push(start*100 + j)
			}
		}(i)
	}

	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				rb.Len()
			}
		}()
	}

	wg.Wait()

	if rb.Len() != rb.Cap() {
		t.Error("Buffer should be at capacity after concurrent operations")
	}
	if rb.Len() != 100 {
		t.Errorf("Len() = %d after concurrent operations, want 100", rb.Len())
	}
}

func BenchmarkPush(b *testing.B) {
	rb := New[int](1000)

	for i := 0; b.Loop(); i++ {
		rb.Push(i)
	}
}

func BenchmarkPop(b *testing.B) {
	rb := New[int](1000)
	for i := range 1000 {
		rb.Push(i)
	}

	for b.Loop() {
		rb.Pop()
		if rb.Len() == 0 {
			for j := range 1000 {
				rb.Push(j)
			}
		}
	}
}

func BenchmarkConcurrentPushPop(b *testing.B) {
	rb := New[int](1000)
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				rb.Push(i)
			} else {
				rb.Pop()
			}
			i++
		}
	})
}

func TestPopCatchUp(t *testing.T) {
	rb := New[int](3)

	rb.Push(1)
	rb.Push(2)
	rb.Push(3)

	rb.Push(4) // displaces 1
	rb.Push(5) // displaces 2
	rb.Push(6) // displaces 3

	// At this point, writePos = 6, readPos = 0, capacity = 3
	// writePos (6) > readPos (0) + capacity (3), so catch-up should trigger
	// First Pop() should trigger catch-up logic and return the oldest valid item (4)
	item, ok := rb.Pop()
	if !ok {
		t.Fatal("Pop() returned ok=false, expected true")
	}
	if item != 4 {
		t.Errorf("Pop() after catch-up = %d, want 4", item)
	}

	item, ok = rb.Pop()
	if !ok || item != 5 {
		t.Errorf("Pop() = (%d, %t), want (5, true)", item, ok)
	}

	item, ok = rb.Pop()
	if !ok || item != 6 {
		t.Errorf("Pop() = (%d, %t), want (6, true)", item, ok)
	}

	item, ok = rb.Pop()
	if ok {
		t.Errorf("Pop() on empty buffer = (%d, %t), want (0, false)", item, ok)
	}
}

func BenchmarkZeroAllocation(b *testing.B) {
	const numItems = 1000
	testData := make([]int, numItems)
	for i := range testData {
		testData[i] = i
	}

	rb := New[int](64)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		rb.Push(testData[i%numItems])
		rb.Pop()
	}
}
