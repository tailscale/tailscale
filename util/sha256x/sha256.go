// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha256x is like crypto/sha256 with extra methods.
// It exports a concrete Hash type
// rather than only returning an interface implementation.
package sha256x

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"unsafe"
)

var _ hash.Hash = (*Hash)(nil)

// Hash is a hash.Hash for SHA-256,
// but has efficient methods for hashing fixed-width integers.
type Hash struct {
	// The optimization is to maintain our own block and
	// only call h.Write with entire blocks.
	// This avoids double-copying of buffers within sha256.digest itself.
	// However, it does mean that sha256.digest.x goes unused,
	// which is a waste of 64B.

	// H is the underlying hash.Hash.
	// The hash.Hash.BlockSize must be equal to sha256.BlockSize.
	// It is exported only for testing purposes.
	H  hash.Hash              // usually a *sha256.digest
	x  [sha256.BlockSize]byte // equivalent to sha256.digest.x
	nx int                    // equivalent to sha256.digest.nx
}

func New() *Hash {
	return &Hash{H: sha256.New()}
}

func (h *Hash) Write(b []byte) (int, error) {
	h.HashBytes(b)
	return len(b), nil
}

func (h *Hash) Sum(b []byte) []byte {
	if h.nx > 0 {
		// This causes block mis-alignment. Future operations will be correct,
		// but are less efficient until Reset is called.
		h.H.Write(h.x[:h.nx])
		h.nx = 0
	}

	// Unfortunately hash.Hash.Sum always causes the input to escape since
	// escape analysis cannot prove anything past an interface method call.
	// Assuming h already escapes, we call Sum with h.x first,
	// and then copy the result to b.
	sum := h.H.Sum(h.x[:0])
	return append(b, sum...)
}

func (h *Hash) Reset() {
	if h.H == nil {
		h.H = sha256.New()
	}
	h.H.Reset()
	h.nx = 0
}

func (h *Hash) Size() int {
	return h.H.Size()
}

func (h *Hash) BlockSize() int {
	return h.H.BlockSize()
}

func (h *Hash) HashUint8(n uint8) {
	// NOTE: This method is carefully written to be inlineable.
	if h.nx <= len(h.x)-1 {
		h.x[h.nx] = n
		h.nx += 1
	} else {
		h.hashUint8Slow(n) // mark "noinline" to keep this within inline budget
	}
}

//go:noinline
func (h *Hash) hashUint8Slow(n uint8) { h.hashUint(uint64(n), 1) }

func (h *Hash) HashUint16(n uint16) {
	// NOTE: This method is carefully written to be inlineable.
	if h.nx <= len(h.x)-2 {
		binary.LittleEndian.PutUint16(h.x[h.nx:], n)
		h.nx += 2
	} else {
		h.hashUint16Slow(n) // mark "noinline" to keep this within inline budget
	}
}

//go:noinline
func (h *Hash) hashUint16Slow(n uint16) { h.hashUint(uint64(n), 2) }

func (h *Hash) HashUint32(n uint32) {
	// NOTE: This method is carefully written to be inlineable.
	if h.nx <= len(h.x)-4 {
		binary.LittleEndian.PutUint32(h.x[h.nx:], n)
		h.nx += 4
	} else {
		h.hashUint32Slow(n) // mark "noinline" to keep this within inline budget
	}
}

//go:noinline
func (h *Hash) hashUint32Slow(n uint32) { h.hashUint(uint64(n), 4) }

func (h *Hash) HashUint64(n uint64) {
	// NOTE: This method is carefully written to be inlineable.
	if h.nx <= len(h.x)-8 {
		binary.LittleEndian.PutUint64(h.x[h.nx:], n)
		h.nx += 8
	} else {
		h.hashUint64Slow(n) // mark "noinline" to keep this within inline budget
	}
}

//go:noinline
func (h *Hash) hashUint64Slow(n uint64) { h.hashUint(uint64(n), 8) }

func (h *Hash) hashUint(n uint64, i int) {
	for ; i > 0; i-- {
		if h.nx == len(h.x) {
			h.H.Write(h.x[:])
			h.nx = 0
		}
		h.x[h.nx] = byte(n)
		h.nx += 1
		n >>= 8
	}
}

func (h *Hash) HashBytes(b []byte) {
	// Nearly identical to sha256.digest.Write.
	if h.nx > 0 {
		n := copy(h.x[h.nx:], b)
		h.nx += n
		if h.nx == len(h.x) {
			h.H.Write(h.x[:])
			h.nx = 0
		}
		b = b[n:]
	}
	if len(b) >= len(h.x) {
		n := len(b) &^ (len(h.x) - 1) // n is a multiple of len(h.x)
		h.H.Write(b[:n])
		b = b[n:]
	}
	if len(b) > 0 {
		h.nx = copy(h.x[:], b)
	}
}

func (h *Hash) HashString(s string) {
	type stringHeader struct {
		p unsafe.Pointer
		n int
	}
	p := (*stringHeader)(unsafe.Pointer(&s))
	b := unsafe.Slice((*byte)(p.p), p.n)
	h.HashBytes(b)
}

// TODO: Add Hash.MarshalBinary and Hash.UnmarshalBinary?
