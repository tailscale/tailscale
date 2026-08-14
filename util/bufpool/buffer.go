// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package bufpool

import (
	"io"
	"sync"
)

// Buffer is like [bytes.Buffer], but grows using the global buffer pool.
// The Grow method returns an error if the buffer cannot be grown.
// A buffer must be obtained via [Get] or [Pool.Get].
type Buffer struct {
	//lint:ignore U1000 intentional unused field
	noShallowCopy [0]sync.Mutex

	parent *Pool

	// buf is the internal buf.
	//	- buf[:off] is the data that has already been read
	//	- buf[off:len(buf)] is the data ready to read
	//	- buf[len(buf):cap(buf)] is the available space to write into
	buf []byte
	off int
}

// Reset resets the buffer to be empty,
// but it retains the underlying storage for use by future writes.
func (b *Buffer) Reset() {
	b.buf = b.buf[:0]
	b.off = 0
}

// Len reports the length of the buffer.
func (b *Buffer) Len() int {
	return len(b.buf) - b.off
}

// Cap reports the capacity of the buffer.
func (b *Buffer) Cap() int {
	return cap(b.buf)
}

// Available report the unused capacity of the buffer.
func (b *Buffer) Available() int {
	return cap(b.buf) - len(b.buf)
}

// AvailableBuffer returns an empty buffer with [Buffer.Available] capacity.
// This buffer is intended to be appended to and
// passed to an immediately succeeding [Buffer.Write] call.
// The buffer is only valid until the next write operation on b.
func (b *Buffer) AvailableBuffer() []byte {
	return b.buf[len(b.buf):]
}

// Bytes returns the underlying buffer.
//
// The caller must ensure that the underlying buffer is no longer in use
// before putting the Buffer pack in the pool.
func (b *Buffer) Bytes() []byte {
	return b.buf[b.off:]
}

// String returns the contents of the unread portion of the buffer as a string.
func (b *Buffer) String() string {
	if b == nil {
		return "<nil>" // special case for debugging
	}
	return string(b.Bytes())
}

// Grow expands the capacity of the buffer to accommodate n additional bytes
// without any further regrowth.
func (b *Buffer) Grow(n int) error {
	if n < 0 {
		panic("negative capacity")
	}
	if cap(b.buf)-len(b.buf) < n {
		b2, err := b.parent.Get(len(b.buf) + n)
		if err != nil {
			return err
		}
		b2.buf = append(b2.buf[:0], b.buf[b.off:]...) // does not allocate
		b.buf, b2.buf = b2.buf, b.buf
		b.off = 0
		b.parent.Put(b2)
	}
	return nil
}

// Next returns a slice containing the next n bytes from the buffer,
// advancing the buffer as if the bytes had been returned by [Buffer.Read].
//
// The caller must ensure that the underlying buffer is no longer in use
// before putting the Buffer pack in the pool.
func (b *Buffer) Next(n int) []byte {
	data := b.buf[b.off : b.off+min(n, b.Len())]
	b.off += len(data)
	return data
}

// Read reads unread bytes from b into p. It implements [io.Reader].
func (b *Buffer) Read(p []byte) (int, error) {
	if b.Len() == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.buf[b.off:])
	b.off += n
	if b.off >= len(b.buf) {
		b.Reset()
	}
	return n, nil
}

// Write writes the provided bytes from p into b. It implements [io.Writer].
func (b *Buffer) Write(p []byte) (int, error) {
	if err := b.Grow(len(p)); err != nil {
		return 0, err
	}
	b.buf = b.buf[:len(b.buf)+len(p)]
	copy(b.buf[len(b.buf)-len(p):], p) // noop if src and dst are the same
	return len(p), nil
}

// ReadFrom reads content from r into b. It implements [io.ReaderFrom].
func (b *Buffer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		// Always ensure there is at least 1 byte of available capacity.
		if err := b.Grow(1); err != nil {
			return n, err
		}

		// Read into the available buffer until io.EOF.
		m, err := r.Read(b.buf[len(b.buf):cap(b.buf)])
		b.buf = b.buf[:len(b.buf)+m]
		n += int64(m)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return n, err
		}
	}
}

// WriteTo writes content from b into w. It implements [io.WriterTo].
func (b *Buffer) WriteTo(w io.Writer) (n int64, err error) {
	if b.Len() > 0 {
		var m int
		m, err = w.Write(b.buf[b.off:])
		n = int64(m)
		b.off += m
	}
	if b.off >= len(b.buf) {
		b.Reset()
	}
	return n, err
}
