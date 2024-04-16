// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ringbuffer contains a fixed-size concurrency-safe generic ring
// buffer.
package ringbuffer

import "sync"

// New creates a new RingBuffer containing at most max items.
func New[T any](max int) *RingBuffer[T] {
	return &RingBuffer[T]{
		max: max,
	}
}

// RingBuffer is a concurrency-safe ring buffer.
type RingBuffer[T any] struct {
	mu  sync.Mutex
	pos int
	buf []T
	max int
}

// Add appends a new item to the RingBuffer, possibly overwriting the oldest
// item in the buffer if it is already full.
//
// It does nothing if rb is nil.
func (rb *RingBuffer[T]) Add(t T) {
	if rb == nil {
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if len(rb.buf) < rb.max {
		rb.buf = append(rb.buf, t)
	} else {
		rb.buf[rb.pos] = t
		rb.pos = (rb.pos + 1) % rb.max
	}
}

// GetAll returns a copy of all the entries in the ring buffer in the order they
// were added.
//
// It returns nil if rb is nil.
func (rb *RingBuffer[T]) GetAll() []T {
	if rb == nil {
		return nil
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	out := make([]T, len(rb.buf))
	for i := range len(rb.buf) {
		x := (rb.pos + i) % rb.max
		out[i] = rb.buf[x]
	}
	return out
}

// Len returns the number of elements in the ring buffer. Note that this value
// could change immediately after being returned if a concurrent caller
// modifies the buffer.
func (rb *RingBuffer[T]) Len() int {
	if rb == nil {
		return 0
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return len(rb.buf)
}

// Clear will empty the ring buffer.
func (rb *RingBuffer[T]) Clear() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.pos = 0
	rb.buf = nil
}
