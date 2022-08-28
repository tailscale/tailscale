// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cstruct provides a helper for decoding binary data that is in the
// form of a padded C structure.
package cstruct

import (
	"errors"
	"io"

	"tailscale.com/util/endian"
)

// Size of a pointer-typed value, in bits
const pointerSize = 32 << (^uintptr(0) >> 63)

// We assume that non-64-bit platforms are 32-bit; we don't expect Go to run on
// a 16- or 8-bit architecture any time soon.
const is64Bit = pointerSize == 64

// Decoder reads and decodes padded fields from a slice of bytes. All fields
// are decoded with native endianness.
//
// Methods of a Decoder do not return errors, but rather store any error within
// the Decoder. The first error can be obtained via the Err method; after the
// first error, methods will return the zero value for their type.
type Decoder struct {
	b    []byte
	off  int
	err  error
	dbuf [8]byte // for decoding
}

// NewDecoder creates a Decoder from a byte slice.
func NewDecoder(b []byte) *Decoder {
	return &Decoder{b: b}
}

var errUnsupportedSize = errors.New("unsupported size")

func padBytes(offset, size int) int {
	if offset == 0 || size == 1 {
		return 0
	}
	remainder := offset % size
	return size - remainder
}

func (d *Decoder) getField(b []byte) error {
	size := len(b)

	// We only support fields that are multiples of 2 (or 1-sized)
	if size != 1 && size&1 == 1 {
		return errUnsupportedSize
	}

	// Fields are aligned to their size
	padBytes := padBytes(d.off, size)
	if d.off+size+padBytes > len(d.b) {
		return io.EOF
	}
	d.off += padBytes

	copy(b, d.b[d.off:d.off+size])
	d.off += size
	return nil
}

// Err returns the first error that was encountered by this Decoder.
func (d *Decoder) Err() error {
	return d.err
}

// Offset returns the current read offset for data in the buffer.
func (d *Decoder) Offset() int {
	return d.off
}

// Byte returns a single byte from the buffer.
func (d *Decoder) Byte() byte {
	if d.err != nil {
		return 0
	}

	if err := d.getField(d.dbuf[0:1]); err != nil {
		d.err = err
		return 0
	}
	return d.dbuf[0]
}

// Byte returns a number of bytes from the buffer based on the size of the
// input slice. No padding is applied.
//
// If an error is encountered or this Decoder has previously encountered an
// error, no changes are made to the provided buffer.
func (d *Decoder) Bytes(b []byte) {
	if d.err != nil {
		return
	}

	// No padding for byte slices
	size := len(b)
	if d.off+size >= len(d.b) {
		d.err = io.EOF
		return
	}
	copy(b, d.b[d.off:d.off+size])
	d.off += size
}

// Uint16 returns a uint16 decoded from the buffer.
func (d *Decoder) Uint16() uint16 {
	if d.err != nil {
		return 0
	}

	if err := d.getField(d.dbuf[0:2]); err != nil {
		d.err = err
		return 0
	}
	return endian.Native.Uint16(d.dbuf[0:2])
}

// Uint32 returns a uint32 decoded from the buffer.
func (d *Decoder) Uint32() uint32 {
	if d.err != nil {
		return 0
	}

	if err := d.getField(d.dbuf[0:4]); err != nil {
		d.err = err
		return 0
	}
	return endian.Native.Uint32(d.dbuf[0:4])
}

// Uint64 returns a uint64 decoded from the buffer.
func (d *Decoder) Uint64() uint64 {
	if d.err != nil {
		return 0
	}

	if err := d.getField(d.dbuf[0:8]); err != nil {
		d.err = err
		return 0
	}
	return endian.Native.Uint64(d.dbuf[0:8])
}

// Uintptr returns a uintptr decoded from the buffer.
func (d *Decoder) Uintptr() uintptr {
	if d.err != nil {
		return 0
	}

	if is64Bit {
		return uintptr(d.Uint64())
	} else {
		return uintptr(d.Uint32())
	}
}

// Int16 returns a int16 decoded from the buffer.
func (d *Decoder) Int16() int16 {
	return int16(d.Uint16())
}

// Int32 returns a int32 decoded from the buffer.
func (d *Decoder) Int32() int32 {
	return int32(d.Uint32())
}

// Int64 returns a int64 decoded from the buffer.
func (d *Decoder) Int64() int64 {
	return int64(d.Uint64())
}
