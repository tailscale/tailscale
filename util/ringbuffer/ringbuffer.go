// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ringbuffer provides a thread-safe generic ring buffer implementation.
//
// A ring buffer is a fixed-size data structure that overwrites the oldest
// entries when full. Unlike buffered channels, writers never block and old
// data is automatically displaced, making it ideal for high-throughput packet
// processing where recent data is more valuable than blocking.
//
// Basic usage:
//
//	rb := ringbuffer.New[Packet](1024)
//
//	// Producer (never blocks, even under burst load)
//	displaced := rb.Push(packet)
//	if displaced { metrics.PacketsDropped.Inc() }
//
//	// Consumer (automatically catches up if it falls behind)
//	if packet, ok := rb.Pop(); ok {
//		processPacket(packet)
//	}
//
// Key properties:
//   - Writers never block (prevents cascading failures)
//   - Congestion friendly under pressure (drops old data vs dropping new data or blocking)
//   - Zero allocations per operation
//   - Thread-safe with simple mutex synchronization
//   - Popped items are zero'd (releasing any internal references)
//   - Performance is similar to a buffered channel
//
// The RingBuffer handles nil receivers gracefully (except Push, which panics
// to prevent silent data loss).
package ringbuffer

import (
	"sync"
)

// New creates a new thread-safe [RingBuffer] with the specified capacity.
// The capacity must be greater than 0.
func New[T any](capacity int) *RingBuffer[T] {
	if capacity <= 0 {
		panic("ringbuffer: capacity must be greater than 0")
	}
	return &RingBuffer[T]{
		buf: make([]T, capacity),
	}
}

// RingBuffer is a thread-safe ring buffer implementation.
// It uses a single mutex to protect all operations, ensuring race-free access.
type RingBuffer[T any] struct {
	mu       sync.Mutex // protects all fields below
	buf      []T        // stores T values directly
	writePos uint64     // monotonically increasing write position
	readPos  uint64     // monotonically increasing read position
}

// Displaced indicates whether a push operation overwrote an existing entry.
type Displaced bool

// Push adds a new item to the ring buffer.
// If the buffer is full, it overwrites the oldest item and returns
// true to indicate that an entry was displaced.
//
// It panics if rb is nil.
func (rb *RingBuffer[T]) Push(item T) Displaced {
	if rb == nil {
		panic("ringbuffer: Push called on nil RingBuffer")
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()

	displaced := rb.writePos >= rb.readPos+uint64(cap(rb.buf))
	bufIdx := rb.writePos % uint64(cap(rb.buf))
	rb.buf[bufIdx] = item
	rb.writePos++

	return Displaced(displaced)
}

// Pop removes and returns the oldest item from the ring buffer.
// It returns the zero value of T and false if the buffer is empty.
//
// It returns nil, false if rb is nil.
func (rb *RingBuffer[T]) Pop() (T, bool) {
	var zero T
	if rb == nil {
		return zero, false
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// reader catch up after writer overrun
	if rb.writePos > rb.readPos+uint64(cap(rb.buf)) {
		rb.readPos = rb.writePos - uint64(cap(rb.buf))
	}

	// buffer is empty
	if rb.readPos >= rb.writePos {
		return zero, false
	}

	bufIdx := rb.readPos % uint64(cap(rb.buf))
	item := rb.buf[bufIdx]
	rb.buf[bufIdx] = zero
	rb.readPos++

	return item, true
}

// Len returns the current number of items in the ring buffer.
// Note that this value could change immediately after being returned
// if a concurrent caller modifies the buffer.
//
// It returns 0 if rb is nil.
func (rb *RingBuffer[T]) Len() int {
	if rb == nil {
		return 0
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()

	return min(cap(rb.buf), int(rb.writePos-rb.readPos))
}

// Cap returns the capacity of the ring buffer.
//
// It returns 0 if rb is nil.
func (rb *RingBuffer[T]) Cap() int {
	if rb == nil {
		return 0
	}
	return cap(rb.buf)
}

// Clear removes all items from the ring buffer.
//
// It does nothing if rb is nil.
func (rb *RingBuffer[T]) Clear() {
	if rb == nil {
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()

	var zero T
	for i := range rb.buf {
		rb.buf[i] = zero
	}
	rb.readPos = rb.writePos
}

// Drain removes and returns all items in the ring buffer in the order
// they were added (oldest first). The buffer will be empty after this operation.
//
// It returns nil if rb is nil.
func (rb *RingBuffer[T]) Drain() []T {
	if rb == nil {
		return nil
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// catch-up after overrun
	if rb.writePos > rb.readPos+uint64(cap(rb.buf)) {
		rb.readPos = rb.writePos - uint64(cap(rb.buf))
	}

	// empty buffer
	if rb.readPos >= rb.writePos {
		return nil
	}

	count := min(int(rb.writePos-rb.readPos), cap(rb.buf))
	result := make([]T, count)
	var zero T
	for i := range count {
		bufIdx := (rb.readPos + uint64(i)) % uint64(cap(rb.buf))
		result[i] = rb.buf[bufIdx]
		rb.buf[bufIdx] = zero
	}
	rb.readPos = rb.writePos

	return result
}
