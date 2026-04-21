// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package iopipe

import (
	"cmp"
	"io"
	"sync"
)

// EphemeralBuffer in an in-memory implementation of [Buffer].
// The zero value is an empty buffer ready for use.
type EphemeralBuffer struct {
	mu     sync.Mutex
	buf    []byte // unread data is in buf[idx:]
	idx    int
	waiter chan struct{}
}

// Len reports the size of the buffer,
// which is the number of written, but unread bytes.
func (b *EphemeralBuffer) Len() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int64(len(b.buf[b.idx:]))
}

// Write writes data to the end of the buffer,
// incrementing Len by the amount of bytes written.
func (b *EphemeralBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)

	// Check if there are any waiters to wake up.
	if len(p) > 0 && b.waiter != nil {
		close(b.waiter)
		b.waiter = nil
	}
	return len(p), nil
}

// Read reads data from the front of the buffer,
// decrementing Len by the amount of bytes read.
// When the buffer is empty, it returns [io.EOF].
func (b *EphemeralBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p2, peekErr := b.peekLocked(len(p))
	n, discErr := b.discardLocked(copy(p, p2))
	return n, cmp.Or(discErr, peekErr)
}

// Peek peeks n bytes from the front of the buffer.
// The buffer is only valid until the next Read, Peek, or Discard call.
// It reports an error if the buffer length is less than n.
func (b *EphemeralBuffer) Peek(n int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peekLocked(n)
}

// Discard discards n bytes from the front of the buffer,
// decrementing Len by the amount of bytes discarded.
// It reports an error if the number of discard bytes is less than n.
func (b *EphemeralBuffer) Discard(n int) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.discardLocked(n)
}

// peekLocked implements Peek while mu is already held.
func (b *EphemeralBuffer) peekLocked(n int) ([]byte, error) {
	switch data := b.buf[b.idx:]; {
	case n < 0:
		return nil, wrapError("peek", errNegative)
	case n <= len(data):
		return data[:n], nil
	default:
		return data, io.EOF
	}
}

// discardLocked implements Discard while mu is already held.
func (b *EphemeralBuffer) discardLocked(n int) (int, error) {
	// Use peek to determine the available bytes to discard
	// and discard by incrementing idx.
	p, err := b.peekLocked(n)
	err = wrapError("discard", err) // remains nil if already nil
	b.idx += len(p)

	// If enough of the buffer has already been read,
	// then move the data to the front.
	if b.idx > len(b.buf)/2 { // more than half the buffer is already read
		// TODO: Allow shrinking the buffer if unused enough?
		m := copy(b.buf[:cap(b.buf)], b.buf[b.idx:]) // copy data to the front
		b.buf = b.buf[:m]
		b.idx = 0
	}

	return len(p), err
}

// Wait returns channel that is closed when the buffer is non-empty.
func (b *EphemeralBuffer) Wait() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buf[b.idx:]) > 0 {
		return alreadyClosed // data is available
	} else if b.waiter == nil {
		b.waiter = make(chan struct{})
	}
	return b.waiter
}
