// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package hashx provides a concrete implementation of [hash.Hash]
// that operates on a particular block size.
package hashx

import (
	"encoding/binary"
	"fmt"
	"hash"
	"unsafe"
)

var _ hash.Hash = (*Block512)(nil)

// Block512 wraps a [hash.Hash] for functions that operate on 512-bit block sizes.
// It has efficient methods for hashing fixed-width integers.
//
// A hashing algorithm that operates on 512-bit block sizes should be used.
// The hash still operates correctly even with misaligned block sizes,
// but operates less efficiently.
//
// Example algorithms with 512-bit block sizes include:
//   - MD4 (https://golang.org/x/crypto/md4)
//   - MD5 (https://golang.org/pkg/crypto/md5)
//   - BLAKE2s (https://golang.org/x/crypto/blake2s)
//   - BLAKE3
//   - RIPEMD (https://golang.org/x/crypto/ripemd160)
//   - SHA-0
//   - SHA-1 (https://golang.org/pkg/crypto/sha1)
//   - SHA-2 (https://golang.org/pkg/crypto/sha256)
//   - Whirlpool
//
// See https://en.wikipedia.org/wiki/Comparison_of_cryptographic_hash_functions#Parameters
// for a list of hash functions and their block sizes.
//
// Block512 assumes that [hash.Hash.Write] never fails and
// never allows the provided buffer to escape.
type Block512 struct {
	hash.Hash

	x  [512 / 8]byte
	nx int
}

// New512 constructs a new Block512 that wraps h.
//
// It reports an error if the block sizes do not match.
// Misaligned block sizes perform poorly, but execute correctly.
// The error may be ignored if performance is not a concern.
func New512(h hash.Hash) (*Block512, error) {
	b := &Block512{Hash: h}
	if len(b.x)%h.BlockSize() != 0 {
		return b, fmt.Errorf("hashx.Block512: inefficient use of hash.Hash with %d-bit block size", 8*h.BlockSize())
	}
	return b, nil
}

// Write hashes the contents of b.
func (h *Block512) Write(b []byte) (int, error) {
	h.HashBytes(b)
	return len(b), nil
}

// Sum appends the current hash to b and returns the resulting slice.
//
// It flushes any partially completed blocks to the underlying [hash.Hash],
// which may cause future operations to be misaligned and less efficient
// until [Block512.Reset] is called.
func (h *Block512) Sum(b []byte) []byte {
	if h.nx > 0 {
		h.Hash.Write(h.x[:h.nx])
		h.nx = 0
	}

	// Unfortunately hash.Hash.Sum always causes the input to escape since
	// escape analysis cannot prove anything past an interface method call.
	// Assuming h already escapes, we call Sum with h.x first,
	// and then copy the result to b.
	sum := h.Hash.Sum(h.x[:0])
	return append(b, sum...)
}

// Reset resets Block512 to its initial state.
// It recursively resets the underlying [hash.Hash].
func (h *Block512) Reset() {
	h.Hash.Reset()
	h.nx = 0
}

// HashUint8 hashes n as a 1-byte integer.
func (h *Block512) HashUint8(n uint8) {
	// NOTE: This method is carefully written to be inlineable.
	if h.nx <= len(h.x)-1 {
		h.x[h.nx] = n
		h.nx += 1
	} else {
		h.hashUint8Slow(n) // mark "noinline" to keep this within inline budget
	}
}

//go:noinline
func (h *Block512) hashUint8Slow(n uint8) { h.hashUint(uint64(n), 1) }

// HashUint16 hashes n as a 2-byte little-endian integer.
func (h *Block512) HashUint16(n uint16) {
	// NOTE: This method is carefully written to be inlineable.
	if h.nx <= len(h.x)-2 {
		binary.LittleEndian.PutUint16(h.x[h.nx:], n)
		h.nx += 2
	} else {
		h.hashUint16Slow(n) // mark "noinline" to keep this within inline budget
	}
}

//go:noinline
func (h *Block512) hashUint16Slow(n uint16) { h.hashUint(uint64(n), 2) }

// HashUint32 hashes n as a 4-byte little-endian integer.
func (h *Block512) HashUint32(n uint32) {
	// NOTE: This method is carefully written to be inlineable.
	if h.nx <= len(h.x)-4 {
		binary.LittleEndian.PutUint32(h.x[h.nx:], n)
		h.nx += 4
	} else {
		h.hashUint32Slow(n) // mark "noinline" to keep this within inline budget
	}
}

//go:noinline
func (h *Block512) hashUint32Slow(n uint32) { h.hashUint(uint64(n), 4) }

// HashUint64 hashes n as a 8-byte little-endian integer.
func (h *Block512) HashUint64(n uint64) {
	// NOTE: This method is carefully written to be inlineable.
	if h.nx <= len(h.x)-8 {
		binary.LittleEndian.PutUint64(h.x[h.nx:], n)
		h.nx += 8
	} else {
		h.hashUint64Slow(n) // mark "noinline" to keep this within inline budget
	}
}

//go:noinline
func (h *Block512) hashUint64Slow(n uint64) { h.hashUint(uint64(n), 8) }

func (h *Block512) hashUint(n uint64, i int) {
	for ; i > 0; i-- {
		if h.nx == len(h.x) {
			h.Hash.Write(h.x[:])
			h.nx = 0
		}
		h.x[h.nx] = byte(n)
		h.nx += 1
		n >>= 8
	}
}

// HashBytes hashes the contents of b.
// It does not explicitly hash the length separately.
func (h *Block512) HashBytes(b []byte) {
	// Nearly identical to sha256.digest.Write.
	if h.nx > 0 {
		n := copy(h.x[h.nx:], b)
		h.nx += n
		if h.nx == len(h.x) {
			h.Hash.Write(h.x[:])
			h.nx = 0
		}
		b = b[n:]
	}
	if len(b) >= len(h.x) {
		n := len(b) &^ (len(h.x) - 1) // n is a multiple of len(h.x)
		h.Hash.Write(b[:n])
		b = b[n:]
	}
	if len(b) > 0 {
		h.nx = copy(h.x[:], b)
	}
}

// HashString hashes the contents of s.
// It does not explicitly hash the length separately.
func (h *Block512) HashString(s string) {
	// TODO: Avoid unsafe when standard hashers implement io.StringWriter.
	// See https://go.dev/issue/38776.
	type stringHeader struct {
		p unsafe.Pointer
		n int
	}
	p := (*stringHeader)(unsafe.Pointer(&s))
	b := unsafe.Slice((*byte)(p.p), p.n)
	h.HashBytes(b)
}

// TODO: Add Hash.MarshalBinary and Hash.UnmarshalBinary?
