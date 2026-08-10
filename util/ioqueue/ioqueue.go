// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package ioqueue provides a concurrent byte queue with monotonic offsets.
//
// A [Buffer] is an unframed stream of bytes:
// many writers may append concurrently to a shared write cursor, and
// many readers may consume from a shared read cursor.
// It is suitable for buffering data before transmission or processing
// elsewhere (for example log or telemetry upload),
// whether the backing store is memory, disk, or a hybrid of the two.
//
// # Buffer semantics
//
// Unlike [io.Pipe], reads and writes do not block each other.
// [Buffer.Write] never blocks.
// [Buffer.Read] and [Buffer.Peek] return immediately with [ErrEmpty]
// when no data is available.
// Waiting for progress is explicit via [Buffer.WaitUntil],
// or helpers such as [WaitLength] and [StreamReader].
//
// The queue is logically infinite;
// implementations and applications are responsible for draining data
// and/or rejecting writes when resource limits are reached.
// Message framing (newlines, length prefixes, COBS, and so on)
// is left to the application.
//
// Progress is tracked with monotonic [Buffer.ReadOffset]
// and [Buffer.WriteOffset] counters.
// [Buffer.Peek] combined with [Buffer.DiscardUntil]
// supports commit-after-success consumption
// (for example peek, upload, then discard).
// [Buffer.DiscardUntil] is a monotonic advance of the shared read cursor,
// so concurrent readers
// (such as an uploader and a size-enforcing discarder)
// cooperate without exclusive leases.
// Peek does not reserve data.
//
// [Buffer] implements [io.Writer] and [io.Reader].
// Pairing a buffer with [io.Copy] drains all currently available bytes
// and stops on [ErrEmpty]
// (or [io.EOF] if the write side is closed and fully drained).
// For a blocking stream that waits for more data, use [StreamReader].
//
// # Empty vs end-of-stream
//
// [ErrEmpty] means the queue is transiently empty;
// more data may arrive.
// Close and other lifecycle operations are not part of [Buffer].
// A concrete type may support closing the write side
// and return [io.EOF] from Read/Peek once closed and drained,
// and should unblock [Buffer.WaitUntil] waiters
// so they do not hang after close.
//
// # Helpers
//
//   - [WaitLength] waits until the buffer is non-empty
//     (and optionally until a length and/or delay policy is met),
//     without reporting which condition fired;
//     callers re-check buffer state afterward.
//   - [DiscardOversize] discards from the front of the buffer
//     until [Buffer.Len] is within a maximum size,
//     for use by a concurrent size-enforcing drain.
//   - [StreamReader] adapts a [Buffer] to a blocking [io.Reader]
//     whose lifetime is bound to a [context.Context]
//     (and to [io.EOF] from the buffer if the write side is closed).
package ioqueue

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"slices"
)

// ErrEmpty indicates that the buffer has no data available to read or peek
// at the current [Buffer.ReadOffset].
// It is a transient condition: more data may arrive later.
// Use [Buffer.WaitUntil] to wait for progress,
// or [StreamReader] for an [io.Reader] that blocks until data is available.
//
// ErrEmpty is distinct from [io.EOF].
// A concrete [Buffer] implementation that supports closing the write side
// may return [io.EOF] to signal that the buffer is closed for writing
// and no further bytes will ever be produced
// (after any remaining buffered data has been consumed).
var ErrEmpty = errors.New("ioqueue: buffer empty")

// Buffer is an infinitely sized ring buffer.
// It is the implementation's or application's responsibility to drain
// and/or avoid writing if it is too full (see [DiscardOversize]).
//
// It does not provide any form of message framing,
// which is the responsibility of the application logic.
// Common framing techniques include:
//   - newline-delimited frames,
//   - length-prefixed frames, or
//   - null-terminated COBS-encoded frames
//     (see [tailscale.com/util/cobs]).
//
// All methods must be safe for concurrent use.
//
// Close and other lifecycle operations are not part of this interface.
// A concrete implementation may support closing the write side and,
// once closed and drained,
// return [io.EOF] from [Buffer.Read] and [Buffer.Peek]
// instead of [ErrEmpty].
// Such an implementation should also ensure that
// [Buffer.WaitUntil] does not block indefinitely after close.
type Buffer interface {
	// Len reports the size of the buffer,
	// which is the number of written, but unread bytes.
	// It is equivalent to atomically subtracting
	// the ReadOffset from the WriteOffset.
	Len() int64

	// WriteOffset is the total number of bytes written.
	// It is an increasing monotonic counter
	// and is always greater than or equal to ReadOffset.
	WriteOffset() int64

	// ReadOffset is the total number of bytes read.
	// It is an increasing monotonic counter
	// and is always less than or equal to WriteOffset.
	ReadOffset() int64

	// Write writes data to the end of the buffer,
	// atomically incrementing Len and WriteOffset
	// by the amount of bytes written.
	// Concurrent Write calls are atomically performed.
	// Write does not block.
	Write([]byte) (int, error)

	// Read reads data from the front of the buffer, atomically decrementing
	// Len and incrementing ReadOffset by the amount of bytes read.
	// It never reads partially written data for a concurrent Write call.
	// It fills the buffer with as much data as is available.
	// Rather than blocking, it returns ErrEmpty when the buffer is empty.
	// Use WaitUntil to block until data is available.
	//
	// A concrete implementation that supports closing the write side
	// may return io.EOF once the buffer is closed for writing
	// and no further bytes will ever be produced
	// (after any remaining data has been read).
	// ErrEmpty must not be used for that permanent condition.
	Read([]byte) (int, error)

	// Peek copies data from the front of the buffer into b
	// without affecting Len or ReadOffset.
	// It never peeks partially written data for a concurrent Write call.
	// It fills the buffer with as much data as is available.
	// If len(b) is greater than Len, then it only copies the available content.
	// It reports the current ReadOffset and the number of bytes copied into b.
	// If the number of available bytes is zero, it reports ErrEmpty.
	//
	// A concrete implementation that supports closing the write side
	// may return io.EOF once the buffer is closed for writing
	// and no further bytes will ever be produced
	// (when no buffered data remains).
	//
	// The content peeked can be later discarded as follows:
	//
	//	readOffset, n, err := buf.Peek(b)
	//	... // make use of b[:n]
	//	_, err := buf.DiscardUntil(readOffset + n)
	Peek(b []byte) (readOffset int64, n int64, err error)

	// DiscardUntil discards bytes from the front of the buffer by
	// incrementing ReadOffset to match the specified readOffset.
	// If readOffset is less than ReadOffset,
	// then ReadOffset is not changed and no error is reported.
	// If readOffset is greater than WriteOffset, then ReadOffset is
	// set to the current WriteOffset and reports [ErrEmpty]
	// (or [io.EOF] if the implementation supports closing the write side).
	// It reports the number of bytes that have been discarded.
	// If readOffset is less than or equal to WriteOffset,
	// it should never report [ErrEmpty] or [io.EOF].
	DiscardUntil(readOffset int64) (n int64, err error)

	// WaitUntil returns a channel that is closed
	// when the WriteOffset exceeds the specified writeOffset.
	//
	// To wait for the buffer to have more than n bytes:
	//
	//	<-b.WaitUntil(b.ReadOffset() + n)
	//
	// This method is useful for blocking until the buffer contains
	// more than n bytes to enforce limits on maximum buffer size
	// or to upload in larger batches for greater efficiency.
	//
	// If a concrete implementation supports closing the write side,
	// it should close outstanding and future WaitUntil channels as needed
	// so waiters do not block indefinitely after close.
	WaitUntil(writeOffset int64) <-chan struct{}
}

var alreadyClosed = func() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

// offsetWaiter is a single offset wait registration.
type offsetWaiter struct {
	offsetTarget int64
	done         chan struct{}
}

// offsetWaiters is a sorted list of offset wait registrations.
// The zero value is ready for use.
// Methods assume the caller serializes access (typically via a mutex).
type offsetWaiters struct{ waiters []offsetWaiter }

// wait returns a channel that is closed when offsetNow exceeds offsetTarget,
// or immediately if that condition already holds or closed is true.
// Multiple waiters for the same offsetTarget share one channel.
func (ws *offsetWaiters) wait(offsetNow, offsetTarget int64, closed bool) <-chan struct{} {
	if offsetNow > offsetTarget || closed {
		return alreadyClosed
	}
	i, found := slices.BinarySearchFunc(ws.waiters, offsetTarget, func(w offsetWaiter, off int64) int {
		return cmp.Compare(w.offsetTarget, off)
	})
	if !found {
		ws.waiters = slices.Insert(ws.waiters, i, offsetWaiter{offsetTarget, make(chan struct{})})
	}
	return ws.waiters[i].done
}

// notify closes and removes every waiter satisfied by offsetNow
// (offsetNow exceeds the waiter's offsetTarget) or by closed.
func (ws *offsetWaiters) notify(offsetNow int64, closed bool) {
	for len(ws.waiters) > 0 && (offsetNow > ws.waiters[0].offsetTarget || closed) {
		close((ws.waiters)[0].done)
		(ws.waiters)[0].done = nil
		ws.waiters = ws.waiters[1:]
	}
}

var errClosed = errors.New("closed buffer")

type ioqueueError struct {
	op  string
	err error
}

func wrapError(op string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if e, ok := err.(*ioqueueError); ok {
		err = e.err // avoid double wrapping
	}
	return &ioqueueError{op: op, err: err}
}

func (e *ioqueueError) Error() string {
	if e.op == "" {
		return fmt.Sprintf("ioqueue: %v", e.err)
	} else {
		return fmt.Sprintf("ioqueue %s: %v", e.op, e.err)
	}
}

func (e *ioqueueError) Unwrap() error {
	return e.err
}
