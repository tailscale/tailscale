// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ioqueue

import (
	"io"
	"math/bits"
	"sync"

	"tailscale.com/types/bools"
)

// Statically verify that VolatileBuffer implements Buffer.
var _ Buffer = (*VolatileBuffer)(nil)

// VolatileBuffer is an in-memory implementation of [Buffer].
// The zero value is an empty buffer ready for use.
//
// Unread data is not durable: it is lost when the process exits.
// Close the write side with [VolatileBuffer.CloseWrite] to signal
// that no further bytes will be produced; subsequent [Buffer.Read]
// and [Buffer.Peek] calls return [io.EOF] once the buffer is drained,
// and outstanding [Buffer.WaitUntil] waiters are unblocked.
type VolatileBuffer struct {
	mu sync.Mutex

	// buf may retain a consumed prefix after reads/discards.
	// Unread data is always the trailing writeOffset-readOffset bytes.
	buf         []byte
	readOffset  int64
	writeOffset int64
	peakLen     int64 // decayed by compactLocked

	closedWrite bool
	waiters     offsetWaiters
}

// Len reports the size of the buffer,
// which is the number of written, but unread bytes.
func (b *VolatileBuffer) Len() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lenLocked()
}

func (b *VolatileBuffer) lenLocked() int64 {
	return b.writeOffset - b.readOffset
}

// WriteOffset is the total number of bytes written.
func (b *VolatileBuffer) WriteOffset() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.writeOffset
}

// ReadOffset is the total number of bytes read.
func (b *VolatileBuffer) ReadOffset() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.readOffset
}

// dataLocked returns the unread portion of buf.
func (b *VolatileBuffer) dataLocked() []byte {
	n := int(b.writeOffset - b.readOffset)
	return b.buf[len(b.buf)-n:]
}

// compactLocked reclaims backing storage after a consume,
// by sliding data forward or allocating a smaller capacity buffer.
func (b *VolatileBuffer) compactLocked() {
	data := b.dataLocked()
	// If already read data is greater than unread data, then compact.
	if len(b.buf) > 2*len(data) {
		b.peakLen = max(b.peakLen, b.lenLocked())
		// If total capacity is 4x greater than the peak Len,
		// then allocate smaller capacity, otherwise slide data to front.
		if int64(cap(b.buf)/4) > b.peakLen && cap(b.buf) > 4<<10 {
			newCap := 2 << bits.Len(uint(b.peakLen)-1)       // double the peak Len, but round up to power-of-2
			newCap = max(newCap, 4<<10)                      // minimum buffer capacity to shrink to
			b.buf = append(make([]byte, 0, newCap), data...) // allocate smaller buffer
		} else {
			b.buf = b.buf[:copy(b.buf, data)] // slide data to the front
		}
		b.peakLen = b.peakLen * 7 / 8 // reduce peakLen by 12.5%
	}
}

// Write writes data to the end of the buffer,
// atomically incrementing Len and WriteOffset
// by the amount of bytes written.
// Write does not block.
// After [CloseWrite], Write returns an error.
func (b *VolatileBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closedWrite {
		return 0, wrapError("write", errClosed)
	}
	b.buf = append(b.buf, p...)
	b.writeOffset += int64(len(p))
	b.peakLen = max(b.peakLen, b.lenLocked())
	b.waiters.notify(b.writeOffset, b.closedWrite)
	return len(p), nil
}

// Read reads data from the front of the buffer, atomically decrementing
// Len and incrementing ReadOffset by the amount of bytes read.
// Rather than blocking, it returns [ErrEmpty] when the buffer is empty.
// After [CloseWrite], it returns [io.EOF] once drained.
func (b *VolatileBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data := b.dataLocked()
	if len(data) == 0 {
		return 0, wrapError("read", bools.IfElse(b.closedWrite, io.EOF, ErrEmpty))
	}
	n := copy(p, data)
	b.readOffset += int64(n)
	b.compactLocked()
	return n, nil
}

// Peek copies data from the front of the buffer into p
// without affecting Len or ReadOffset.
// It reports the current ReadOffset and the number of bytes copied.
// If no bytes are available, it reports [ErrEmpty],
// or [io.EOF] after [VolatileBuffer.CloseWrite] once drained.
func (b *VolatileBuffer) Peek(p []byte) (readOffset int64, n int64, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	readOffset = b.readOffset
	data := b.dataLocked()
	if len(data) == 0 {
		return readOffset, 0, wrapError("peek", bools.IfElse(b.closedWrite, io.EOF, ErrEmpty))
	}
	return readOffset, int64(copy(p, data)), nil
}

// DiscardUntil discards bytes from the front of the buffer by
// incrementing ReadOffset to match the specified readOffset.
// See [Buffer.DiscardUntil] for full semantics.
func (b *VolatileBuffer) DiscardUntil(readOffset int64) (n int64, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if readOffset <= b.readOffset {
		return 0, nil
	}
	if readOffset > b.writeOffset {
		err = wrapError("discard", bools.IfElse(b.closedWrite, io.EOF, ErrEmpty))
	}
	readOffset = min(readOffset, b.writeOffset)
	n = readOffset - b.readOffset
	b.readOffset = readOffset
	b.compactLocked()
	return n, err
}

// WaitUntil returns a channel that is closed when WriteOffset exceeds
// the specified writeOffset, or when the write side is closed via
// [CloseWrite] (so waiters do not block indefinitely after close).
//
// Multiple waiters for the same writeOffset share one channel.
func (b *VolatileBuffer) WaitUntil(writeOffset int64) <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.waiters.wait(b.writeOffset, writeOffset, b.closedWrite)
}

// CloseWrite closes the write side of the buffer.
// After CloseWrite, [Write] fails, [Read]/[Peek] return [io.EOF]
// once all buffered data has been consumed, and all [WaitUntil]
// waiters are unblocked.
// CloseWrite is idempotent and returns an error if already closed.
func (b *VolatileBuffer) CloseWrite() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closedWrite {
		return wrapError("close", errClosed)
	}
	b.closedWrite = true
	b.waiters.notify(b.writeOffset, b.closedWrite)
	return nil
}
