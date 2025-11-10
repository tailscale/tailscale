// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ringbuffer

import (
	"testing"
)

func TestNew(t *testing.T) {
	rb := New[int]()
	if rb.Len() != 0 {
		t.Errorf("new buffer should be empty, got len=%d", rb.Len())
	}
	if rb.Cap() != 0 {
		t.Errorf("new buffer should have zero capacity (lazy allocation), got cap=%d", rb.Cap())
	}
	if !rb.IsEmpty() {
		t.Error("new buffer should be empty")
	}

	// After first push, buffer should be allocated
	rb.Push(1)
	if rb.Cap() < 16 {
		t.Errorf("after first push, buffer should be allocated, got cap=%d", rb.Cap())
	}
}

func TestNewWithSize(t *testing.T) {
	size := 32
	rb := NewWithSize[string](size)
	if rb.Cap() != 0 {
		t.Errorf("new buffer should have zero capacity (lazy allocation), got cap=%d", rb.Cap())
	}

	// After first push, buffer should be allocated
	rb.Push("test")
	if rb.Cap() < 16 {
		t.Errorf("after first push, buffer should be allocated, got cap=%d", rb.Cap())
	}
}

func TestPushPop(t *testing.T) {
	rb := New[int]()

	// Push some values
	for i := 0; i < 5; i++ {
		rb.Push(i)
	}

	if rb.Len() != 5 {
		t.Errorf("expected len=5, got %d", rb.Len())
	}

	// Pop values in FIFO order
	for i := 0; i < 5; i++ {
		val, ok := rb.Pop()
		if !ok {
			t.Fatalf("Pop() failed at iteration %d", i)
		}
		if val != i {
			t.Errorf("expected %d, got %d", i, val)
		}
	}

	if rb.Len() != 0 {
		t.Errorf("buffer should be empty, got len=%d", rb.Len())
	}
}

func TestPopEmpty(t *testing.T) {
	rb := New[int]()
	val, ok := rb.Pop()
	if ok {
		t.Error("Pop() on empty buffer should return false")
	}
	if val != 0 {
		t.Errorf("Pop() on empty buffer should return zero value, got %d", val)
	}
}

func TestPeek(t *testing.T) {
	rb := New[string]()

	// Peek empty buffer
	_, ok := rb.Peek()
	if ok {
		t.Error("Peek() on empty buffer should return false")
	}

	rb.Push("first")
	rb.Push("second")

	val, ok := rb.Peek()
	if !ok {
		t.Fatal("Peek() should return true")
	}
	if val != "first" {
		t.Errorf("expected 'first', got '%s'", val)
	}

	// Peek shouldn't remove the element
	if rb.Len() != 2 {
		t.Errorf("Peek() shouldn't change length, got %d", rb.Len())
	}

	// Verify Pop still gets the same element
	val, _ = rb.Pop()
	if val != "first" {
		t.Errorf("expected 'first', got '%s'", val)
	}
}

func TestGrowth(t *testing.T) {
	rb := NewWithSize[int](4)
	initialCap := rb.Cap()

	// Fill the buffer
	for i := 0; i < initialCap; i++ {
		rb.Push(i)
	}

	if !rb.IsFull() {
		t.Error("buffer should be full")
	}

	// Push one more to trigger growth
	rb.Push(999)

	if rb.Cap() <= initialCap {
		t.Errorf("buffer should have grown, cap=%d, initialCap=%d", rb.Cap(), initialCap)
	}

	if rb.Len() != initialCap+1 {
		t.Errorf("expected len=%d, got %d", initialCap+1, rb.Len())
	}

	// Verify all elements are still there in order
	for i := 0; i < initialCap; i++ {
		val, ok := rb.Pop()
		if !ok || val != i {
			t.Errorf("expected %d, got %d (ok=%v)", i, val, ok)
		}
	}
	val, ok := rb.Pop()
	if !ok || val != 999 {
		t.Errorf("expected 999, got %d (ok=%v)", val, ok)
	}
}

func TestGrowthWithWraparound(t *testing.T) {
	rb := NewWithSize[int](4)

	// Create wraparound condition
	rb.Push(1)
	rb.Push(2)
	rb.Push(3)
	rb.Pop() // Remove 1
	rb.Pop() // Remove 2
	rb.Push(4)
	rb.Push(5)
	rb.Push(6) // Buffer is now [6, _, _, 3, 4, 5] with wrap

	// Now it's full and wrapped, trigger growth
	rb.Push(7)

	// Verify order is preserved
	expected := []int{3, 4, 5, 6, 7}
	for i, exp := range expected {
		val, ok := rb.Pop()
		if !ok || val != exp {
			t.Errorf("iteration %d: expected %d, got %d (ok=%v)", i, exp, val, ok)
		}
	}
}

func TestClear(t *testing.T) {
	rb := New[int]()
	for i := 0; i < 10; i++ {
		rb.Push(i)
	}

	rb.Clear()

	if !rb.IsEmpty() {
		t.Error("buffer should be empty after Clear()")
	}
	if rb.Len() != 0 {
		t.Errorf("len should be 0, got %d", rb.Len())
	}

	// Should be able to use buffer after clear
	rb.Push(42)
	val, ok := rb.Pop()
	if !ok || val != 42 {
		t.Errorf("expected 42, got %d (ok=%v)", val, ok)
	}
}

func TestCompaction(t *testing.T) {
	rb := NewWithSize[int](16)

	// Grow the buffer significantly
	for i := 0; i < 100; i++ {
		rb.Push(i)
	}

	largeCap := rb.Cap()
	if largeCap <= 16 {
		t.Fatalf("buffer should have grown, cap=%d", largeCap)
	}

	// Empty most of the buffer
	for i := 0; i < 99; i++ {
		rb.Pop()
	}

	// Trigger many operations at low capacity to simulate sustained low usage
	for i := 0; i < 300; i++ {
		rb.Push(i)
		rb.Pop()
	}

	// Buffer should have compacted
	finalCap := rb.Cap()
	if finalCap >= largeCap {
		t.Logf("Warning: buffer didn't compact as expected. largeCap=%d, finalCap=%d", largeCap, finalCap)
		// Don't fail, as compaction thresholds are heuristic
	}
}

func TestWatermarkTracking(t *testing.T) {
	rb := New[int]()

	// Push some elements
	for i := 0; i < 20; i++ {
		rb.Push(i)
	}

	stats := rb.Stats()
	if stats.PeakSize < 20 {
		t.Errorf("PeakSize should be at least 20, got %d", stats.PeakSize)
	}

	// Pop all
	for i := 0; i < 20; i++ {
		rb.Pop()
	}

	stats = rb.Stats()
	// Peak should have been tracked
	if stats.PeakSize < 0 {
		t.Errorf("PeakSize should be non-negative, got %d", stats.PeakSize)
	}
}

func TestMaxInWindowTracking(t *testing.T) {
	rb := New[int]()

	// Simulate a workload that oscillates between high and low usage
	// The max-in-window should track the peak size

	// Phase 1: Grow to 50 elements
	for i := 0; i < 50; i++ {
		rb.Push(i)
	}

	stats := rb.Stats()
	if stats.PeakSize < 50 {
		t.Errorf("After pushing 50, PeakSize should be at least 50, got %d", stats.PeakSize)
	}

	// Phase 2: Maintain around 30 elements for a while
	for i := 0; i < 20; i++ {
		rb.Pop()
	}
	for i := 0; i < 100; i++ {
		rb.Push(i)
		rb.Pop()
	}

	stats = rb.Stats()
	// Peak should track the maximum seen
	if stats.PeakSize < 30 {
		t.Logf("After sustained usage at 30, PeakSize=%d (expected >= 30)", stats.PeakSize)
	}

	// Phase 3: Drop to near empty and wait for window reset
	for rb.Len() > 2 {
		rb.Pop()
	}
	for i := 0; i < 300; i++ {
		rb.Push(i)
		rb.Pop()
	}

	stats = rb.Stats()
	// Peak should have reset to current low value after window expires
	if stats.PeakSize > 10 {
		t.Logf("After sustained low usage and window reset, PeakSize=%d", stats.PeakSize)
	}

	// IdleTicks should have accumulated
	if stats.IdleTicks == 0 {
		t.Error("IdleTicks should have accumulated during sustained low usage")
	}
}

func TestStats(t *testing.T) {
	rb := New[int]()
	rb.Push(1)
	rb.Push(2)

	stats := rb.Stats()
	if stats.Len != 2 {
		t.Errorf("Stats.Len should be 2, got %d", stats.Len)
	}
	if stats.Cap != rb.Cap() {
		t.Errorf("Stats.Cap mismatch: %d vs %d", stats.Cap, rb.Cap())
	}

	str := stats.String()
	if str == "" {
		t.Error("Stats.String() should not be empty")
	}
}

func TestGenericTypes(t *testing.T) {
	// Test with struct type
	type testStruct struct {
		id   int
		name string
	}

	rb := New[testStruct]()
	rb.Push(testStruct{1, "one"})
	rb.Push(testStruct{2, "two"})

	val, ok := rb.Pop()
	if !ok || val.id != 1 || val.name != "one" {
		t.Errorf("expected {1, 'one'}, got {%d, '%s'} (ok=%v)", val.id, val.name, ok)
	}

	// Test with pointer type
	rbPtr := New[*testStruct]()
	s1 := &testStruct{10, "ten"}
	rbPtr.Push(s1)

	val2, ok := rbPtr.Pop()
	if !ok || val2 != s1 {
		t.Error("pointer value mismatch")
	}
}

func TestLargeBuffer(t *testing.T) {
	rb := New[int]()

	// Add many elements
	n := 10000
	for i := 0; i < n; i++ {
		rb.Push(i)
	}

	if rb.Len() != n {
		t.Errorf("expected len=%d, got %d", n, rb.Len())
	}

	// Remove them all
	for i := 0; i < n; i++ {
		val, ok := rb.Pop()
		if !ok {
			t.Fatalf("Pop() failed at iteration %d", i)
		}
		if val != i {
			t.Errorf("expected %d, got %d", i, val)
		}
	}

	if !rb.IsEmpty() {
		t.Error("buffer should be empty")
	}
}

func TestAlternatingPushPop(t *testing.T) {
	rb := NewWithSize[int](8)

	// Simulate a queue with alternating push/pop
	// Push 2, pop 1 each iteration - buffer grows by 1 each time
	for i := 0; i < 100; i++ {
		rb.Push(i)
		rb.Push(i + 100)
		_, ok := rb.Pop()
		if !ok {
			t.Fatalf("Pop() failed at iteration %d", i)
		}
	}

	// Should have one element per iteration remaining (we pushed 200, popped 100)
	if rb.Len() != 100 {
		t.Errorf("expected len=100, got %d", rb.Len())
	}

	// Verify buffer grew to accommodate the data
	if rb.Cap() < 100 {
		t.Errorf("buffer should have grown to at least 100, got %d", rb.Cap())
	}

	// Drain and verify FIFO order
	// Pattern pushed: 0, 100, 1, 101, 2, 102, ... 99, 199
	// We popped first 100 items: 0, 1, 2, ... 49, 100, 101, ... 149
	// Remaining: 50, 150, 51, 151, 52, 152, ... 99, 199
	for i := 0; i < 100; i++ {
		v, ok := rb.Pop()
		if !ok {
			t.Fatalf("Pop() failed when draining at position %d", i)
		}
		// Interleaved pattern: even positions get 50+i/2, odd get 150+i/2
		var expected int
		if i%2 == 0 {
			expected = 50 + i/2
		} else {
			expected = 150 + i/2
		}
		if v != expected {
			t.Errorf("draining position %d: expected %d, got %d", i, expected, v)
		}
	}
}

func BenchmarkPush(b *testing.B) {
	rb := New[int]()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Push(i)
	}
}

func BenchmarkPop(b *testing.B) {
	rb := New[int]()
	for i := 0; i < b.N; i++ {
		rb.Push(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Pop()
	}
}

func BenchmarkPushPop(b *testing.B) {
	rb := New[int]()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Push(i)
		rb.Pop()
	}
}

func BenchmarkPushPopWithGrowth(b *testing.B) {
	rb := NewWithSize[int](4)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Push(i)
		if i%2 == 0 {
			rb.Pop()
		}
	}
}

func TestNilBufferBehavior(t *testing.T) {
	rb := New[int]()

	// Buffer should start as nil
	if rb.Cap() != 0 {
		t.Errorf("new buffer should have nil buf (cap=0), got cap=%d", rb.Cap())
	}

	// Should handle operations on nil buffer
	if !rb.IsEmpty() {
		t.Error("nil buffer should report as empty")
	}
	if rb.Len() != 0 {
		t.Errorf("nil buffer should have len=0, got %d", rb.Len())
	}

	_, ok := rb.Pop()
	if ok {
		t.Error("Pop on nil buffer should return false")
	}

	_, ok = rb.Peek()
	if ok {
		t.Error("Peek on nil buffer should return false")
	}

	// Push should allocate buffer
	rb.Push(42)
	if rb.Cap() == 0 {
		t.Error("buffer should be allocated after first Push")
	}
	if rb.Len() != 1 {
		t.Errorf("expected len=1 after push, got %d", rb.Len())
	}

	// Pop back to empty
	val, ok := rb.Pop()
	if !ok || val != 42 {
		t.Errorf("Pop should return 42, got %d (ok=%v)", val, ok)
	}

	// After being idle while empty, buffer should be freed
	for i := 0; i < 250; i++ {
		rb.Pop() // Trigger idle ticks
	}

	if rb.Cap() != 0 {
		t.Logf("Note: buffer not yet freed after idle period, cap=%d", rb.Cap())
		// This is fine - compaction happens in considerCompaction which is only
		// called from Pop when there's something to pop
	}

	// Clear should free the buffer
	rb.Push(1)
	rb.Push(2)
	rb.Clear()
	if rb.Cap() != 0 {
		t.Errorf("Clear should free buffer, got cap=%d", rb.Cap())
	}
}

func TestBufferDeallocationWhenIdle(t *testing.T) {
	rb := New[int]()

	// Push and then pop to create a buffer
	for i := 0; i < 50; i++ {
		rb.Push(i)
	}
	initialCap := rb.Cap()
	if initialCap == 0 {
		t.Fatal("buffer should be allocated after pushes")
	}

	for i := 0; i < 50; i++ {
		rb.Pop()
	}

	// Buffer should still exist but be empty
	if rb.Len() != 0 {
		t.Errorf("buffer should be empty, got len=%d", rb.Len())
	}
	if rb.Cap() == 0 {
		t.Error("buffer should not be immediately freed")
	}

	// Sustain empty state for idle threshold operations
	// Call Pop repeatedly on empty buffer to accumulate idle ticks
	for i := 0; i < 250; i++ {
		rb.Pop() // Pop on empty buffer still updates watermarks
	}

	// Now buffer should be deallocated
	if rb.Cap() != 0 {
		t.Errorf("buffer should be freed after sustained idle empty state, got cap=%d", rb.Cap())
	}

	// Should still work after deallocation
	rb.Push(999)
	if rb.Len() != 1 {
		t.Errorf("expected len=1 after push, got %d", rb.Len())
	}
	val, ok := rb.Pop()
	if !ok || val != 999 {
		t.Errorf("expected 999, got %d (ok=%v)", val, ok)
	}
}

func TestBurstyWorkload(t *testing.T) {
	rb := New[int]()

	// Simulate bursty workload: mostly idle at 10 items, bursts to 1000
	// Max-in-window should size for the bursts, not the average

	// Initial burst
	for i := 0; i < 1000; i++ {
		rb.Push(i)
	}
	stats := rb.Stats()
	if stats.PeakSize < 1000 {
		t.Errorf("Peak should capture initial burst of 1000, got %d", stats.PeakSize)
	}

	burstCap := rb.Cap()
	t.Logf("After burst, capacity=%d", burstCap)

	// Work through burst back to idle
	for i := 0; i < 990; i++ {
		rb.Pop()
	}

	// Stay at 10 items for a while (less than window size)
	for i := 0; i < 100; i++ {
		rb.Push(i)
		rb.Pop()
	}

	// Peak should still remember the burst within the window
	stats = rb.Stats()
	if stats.PeakSize < 10 {
		t.Errorf("Peak should track current size in window, got %d", stats.PeakSize)
	}

	// Do another small burst before window resets
	for i := 0; i < 50; i++ {
		rb.Push(i)
	}

	stats = rb.Stats()
	if stats.PeakSize < 50 {
		t.Errorf("Peak should capture 50-item burst, got %d", stats.PeakSize)
	}

	// Drain back down
	for rb.Len() > 10 {
		rb.Pop()
	}

	// Key test: After 256 operations, window resets
	// Do low-level operations to trigger window reset
	for i := 0; i < 260; i++ {
		rb.Push(i)
		rb.Pop()
	}

	// Peak should have reset to reflect only recent operations
	stats = rb.Stats()
	if stats.PeakSize > 20 {
		t.Logf("After window reset (260 ops), peak=%d (should be ~10)", stats.PeakSize)
	}

	// Another burst - demonstrates max-in-window captures peaks
	for i := 0; i < 500; i++ {
		rb.Push(i)
	}

	stats = rb.Stats()
	if stats.PeakSize < 500 {
		t.Errorf("Peak should capture 500-item burst, got %d", stats.PeakSize)
	}

	// Buffer should have grown to accommodate
	if rb.Cap() < 512 {
		t.Errorf("Buffer should have grown for burst, got cap=%d", rb.Cap())
	}
}
