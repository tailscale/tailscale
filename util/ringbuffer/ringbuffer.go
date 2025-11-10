// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ringbuffer provides a generic adaptive ring buffer implementation.
package ringbuffer

import (
	"fmt"
)

// RingBuffer is a generic circular buffer that can grow when full and compact
// when oversized. It tracks size watermarks to determine when compaction is
// appropriate.
type RingBuffer[T any] struct {
	buf   []T
	head  int // index of the first element
	tail  int // index of the next write position
	count int // number of elements in the buffer

	// Watermark tracking for compaction decisions using max-in-window
	maxInWindow   int // peak count in current window
	windowCounter int // operations since window reset
	idleTicks     int // consecutive operations at low utilization
}

const (
	initialSize   = 16
	minSize       = 16
	windowSize    = 256  // Reset max tracking every N operations
	idleThreshold = 200  // Operations at low utilization before compaction
	lowUtilPct    = 0.25 // Utilization threshold for considering buffer idle
	peakHeadroom  = 1.5  // Headroom multiplier for compaction target
	compactRatio  = 2    // Only compact if capacity > target * compactRatio
)

// New creates a new RingBuffer with default settings.
// The buffer is initially nil and will be allocated on first push.
func New[T any]() *RingBuffer[T] {
	return &RingBuffer[T]{}
}

// NewWithSize creates a new RingBuffer with a specific initial size.
// The buffer is initially nil and will be allocated on first push.
func NewWithSize[T any](size int) *RingBuffer[T] {
	if size < 1 {
		size = initialSize
	}
	return &RingBuffer[T]{}
}

// Push adds an element to the ring buffer. If the buffer is full, it will grow.
func (rb *RingBuffer[T]) Push(item T) {
	// Lazy allocate buffer on first push
	if rb.buf == nil {
		rb.buf = make([]T, initialSize)
	} else if rb.count == len(rb.buf) {
		rb.grow()
	}

	rb.buf[rb.tail] = item
	rb.tail = (rb.tail + 1) % len(rb.buf)
	rb.count++

	rb.updateWatermark()
}

// Pop removes and returns the oldest element from the ring buffer.
// Returns the zero value and false if the buffer is empty.
func (rb *RingBuffer[T]) Pop() (T, bool) {
	if rb.count == 0 {
		var zero T
		// Update watermark even on empty pop to track idle time
		rb.updateWatermark()
		rb.considerCompaction()
		return zero, false
	}

	item := rb.buf[rb.head]
	var zero T
	rb.buf[rb.head] = zero // clear reference for GC
	rb.head = (rb.head + 1) % len(rb.buf)
	rb.count--

	rb.updateWatermark()
	rb.considerCompaction()

	return item, true
}

// Peek returns the oldest element without removing it.
// Returns the zero value and false if the buffer is empty.
func (rb *RingBuffer[T]) Peek() (T, bool) {
	if rb.count == 0 {
		var zero T
		return zero, false
	}
	return rb.buf[rb.head], true
}

// Len returns the number of elements in the buffer.
func (rb *RingBuffer[T]) Len() int {
	return rb.count
}

// Cap returns the current capacity of the underlying buffer.
func (rb *RingBuffer[T]) Cap() int {
	if rb.buf == nil {
		return 0
	}
	return len(rb.buf)
}

// IsEmpty returns true if the buffer contains no elements.
func (rb *RingBuffer[T]) IsEmpty() bool {
	return rb.count == 0
}

// IsFull returns true if the buffer is at capacity.
func (rb *RingBuffer[T]) IsFull() bool {
	return rb.count == len(rb.buf)
}

// Clear removes all elements from the buffer and resets watermarks.
func (rb *RingBuffer[T]) Clear() {
	// Release buffer to save memory
	rb.buf = nil
	rb.head = 0
	rb.tail = 0
	rb.count = 0
	rb.resetWatermarks()
}

// grow doubles the capacity of the ring buffer.
func (rb *RingBuffer[T]) grow() {
	newSize := len(rb.buf) * 2
	if newSize == 0 {
		newSize = initialSize
	}
	rb.resize(newSize)
}

// resize changes the capacity of the ring buffer.
func (rb *RingBuffer[T]) resize(newSize int) {
	if newSize < rb.count {
		// Can't resize smaller than current content
		newSize = rb.count
	}

	newBuf := make([]T, newSize)

	// Copy elements in order from head to tail
	if rb.count > 0 {
		if rb.head < rb.tail {
			copy(newBuf, rb.buf[rb.head:rb.tail])
		} else {
			// Wrapped around
			n := copy(newBuf, rb.buf[rb.head:])
			copy(newBuf[n:], rb.buf[:rb.tail])
		}
	}

	rb.buf = newBuf
	rb.head = 0
	rb.tail = rb.count
}

// updateWatermark tracks the peak size within a sliding window.
func (rb *RingBuffer[T]) updateWatermark() {
	// Track maximum in this window
	if rb.count > rb.maxInWindow {
		rb.maxInWindow = rb.count
	}

	// Reset window periodically
	rb.windowCounter++
	if rb.windowCounter >= windowSize {
		rb.maxInWindow = rb.count
		rb.windowCounter = 0
	}

	// Track consecutive operations at low utilization
	if rb.buf == nil {
		rb.idleTicks++
	} else if rb.count < (len(rb.buf) >> 2) { // count < capacity/4
		rb.idleTicks++
	} else {
		rb.idleTicks = 0
	}
}

// considerCompaction checks if the buffer should be compacted.
func (rb *RingBuffer[T]) considerCompaction() {
	// If empty and idle for a while, free the buffer completely
	if rb.count == 0 && rb.idleTicks >= idleThreshold {
		rb.buf = nil
		rb.head = 0
		rb.tail = 0
		rb.idleTicks = 0
		return
	}

	// Only consider compaction if we're significantly oversized
	if rb.buf == nil || len(rb.buf) <= minSize {
		return
	}

	// If buffer has been underutilized for a while, compact it
	if rb.idleTicks >= idleThreshold {
		// Target size based on peak in window + headroom, rounded up to power of 2
		targetSize := (rb.maxInWindow * 3) >> 1 // maxInWindow * 1.5
		if targetSize < minSize {
			targetSize = minSize
		}

		// Round up to next power of 2 for efficient allocation
		targetSize = nextPowerOf2(targetSize)

		// Only compact if we can save significant space
		if len(rb.buf) > targetSize*compactRatio {
			rb.resize(targetSize)
			rb.idleTicks = 0
			rb.maxInWindow = rb.count
			rb.windowCounter = 0
		}
	}
}

// nextPowerOf2 returns the next power of 2 greater than or equal to n.
func nextPowerOf2(n int) int {
	if n <= 0 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	n++
	return n
}

// resetWatermarks clears watermark tracking state.
func (rb *RingBuffer[T]) resetWatermarks() {
	rb.maxInWindow = 0
	rb.windowCounter = 0
	rb.idleTicks = 0
}

// Stats returns statistics about the ring buffer's behavior.
func (rb *RingBuffer[T]) Stats() Stats {
	var utilization float64
	cap := 0
	if rb.buf != nil {
		cap = len(rb.buf)
		utilization = float64(rb.count) / float64(cap)
	}
	return Stats{
		Len:         rb.count,
		Cap:         cap,
		PeakSize:    rb.maxInWindow,
		IdleTicks:   rb.idleTicks,
		Utilization: utilization,
	}
}

// Stats contains statistics about ring buffer usage.
type Stats struct {
	Len         int     // current number of elements
	Cap         int     // current capacity
	PeakSize    int     // peak size in current window
	IdleTicks   int     // consecutive low-utilization operations
	Utilization float64 // current utilization (len/cap)
}

func (s Stats) String() string {
	return fmt.Sprintf("RingBuffer{len=%d, cap=%d, peak=%d, util=%.2f%%, idle=%d}",
		s.Len, s.Cap, s.PeakSize, s.Utilization*100, s.IdleTicks)
}
