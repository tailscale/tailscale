// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package cobs implements Consistent Overhead Byte Stuffing (COBS),
// a technique for reliable packet framing over serial byte streams.
//
// COBS transforms any arbitrary payload such that the zero byte is guaranteed
// to never appear in the encoded output. A zero byte can then be appended
// as an unambiguous frame delimiter without colliding with the payload data.
//
// The encoding has the following properties:
//
//   - Lossless and reversible. Decoding recovers the original payload exactly.
//
//   - Non-zero payload bytes are never modified. Only zero bytes are removed
//     from the encoded form and replaced by length-prefix overhead bytes.
//
//   - The zero byte is guaranteed to never appear in encoded output, so a
//     trailing null terminator byte can be used to delimit frames in a byte stream.
//
//   - Overhead is tightly bounded in the worst case, unlike PPP byte stuffing
//     (up to 100% expansion) or HDLC bit stuffing (up to 20% expansion).
//     For n > 0 payload bytes, encoded size is at most n + ⌈n/254⌉ bytes.
//     An empty payload encodes to a single byte.
//
//   - Longer frames add at most one overhead byte per 254 bytes of data
//     (about 0.4% for large frames, rounded up to whole bytes).
//     This makes maximum frame size predictable, which matters for devices with
//     fixed MTUs or hard transmission-time limits.
//
// Framing convention: AppendEncode produces COBS-encoded payload only;
// callers typically append a null delimiter when writing to the wire.
// AppendDecode expects the input without the delimiter.
//
// See https://www.stuartcheshire.org/papers/COBSforToN.pdf
package cobs

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"slices"
)

// MaxEncodedLen is the longest possible length for a COBS-encoded output
// for some payload of length n. The encoded length does not include
// the trailing null terminator byte.
//
// Invariant: len(AppendEncode(nil, dec)) <= MaxEncodedLen(len(dec))
func MaxEncodedLen(n int) int {
	n = max(n, 0)
	return n + max(1, (n+253)/254)
}

// MinDecodedLen is the shortest possible length for a decoded payload
// from a COBS-encoded input of a length of n,
// where n does not include the trailing null terminator byte.
//
// Invariant: len(AppendDecode(nil, enc)) >= MinDecodedLen(len(enc))
func MinDecodedLen(n int) int {
	n = max(n, 0)
	return n - (n+254)/255
}

// AppendEncode appends the encoded bytes of src to the end of dst.
// The COBS-encoded output never contains null bytes and
// therefore also lacks a trailing null terminator byte;
// use [AppendNull] to append the trailing null terminator byte if needed.
//
// The src and dst buffers may exactly overlap. For example, it is valid to do:
//
//	b = AppendEncode(b[:0], b)
func AppendEncode(dst, src []byte) []byte {
	// Forward encoding is only safe if dst and src do not overlap.
	// Reverse encoding is always safe, but is ~2-8x slower
	// (but can avoid the need for allocating an intermediate buffer).
	if cap(dst) == len(dst) || cap(src) == 0 || &dst[:cap(dst)][len(dst)] != &src[:cap(src)][0] {
		return appendEncodeForward(dst, src)
	} else {
		return appendEncodeReverse(dst, src)
	}
}

func appendEncodeForward(dst, src []byte) []byte {
	dst = slices.Grow(dst, MaxEncodedLen(len(src)))
	for {
		numNonZero := bytes.IndexByte(src, '\x00')
		if numNonZero < 0 {
			numNonZero = len(src)
		}

		// As a space optimization, the last empty block may be dropped
		// if it follows a full block.
		elideLastEmpty := numNonZero > 0 && numNonZero%254 == 0 && numNonZero == len(src)

		// Emit zero or more full blocks, followed by a non-full block.
		for ; numNonZero >= 254; numNonZero -= 254 {
			dst = append(append(dst, 254+1), src[:254]...)
			src = src[254:]
		}
		if !elideLastEmpty {
			dst = append(append(dst, byte(numNonZero+1)), src[:numNonZero]...)
			src = src[numNonZero:]
		}

		// Finished block, check termination condition and strip zero
		// that is implicitly encoded by previous non-full block.
		if len(src) == 0 {
			break
		}
		if len(src) > 0 && src[0] == '\x00' {
			src = src[1:]
		}

		// As a runtime optimization, specially handle many consecutive zeros.
		for len(src) >= 8 && binary.LittleEndian.Uint64(src) == 0x0000000000000000 {
			dst = binary.LittleEndian.AppendUint64(dst, 0x0101010101010101)
			src = src[8:]
		}
	}
	return dst
}

func appendEncodeReverse(dst, src []byte) []byte {
	// In order to handle appending into an overlapping buffer,
	// first count the number of overhead bytes,
	// and then encode the input in reverse.

	// Extend the dst for the number of overhead bytes.
	numPrefix := len(dst)
	numOverhead := numOverhead(src)
	dst = slices.Grow(dst, len(src)+numOverhead)
	dst = dst[:len(dst)+len(src)+numOverhead]

	// Process the buffers in reverse order.
	dstIdx := len(dst)
	srcIdx := len(src)
	for dstIdx > numPrefix {
		// As a runtime optimization, specially handle many consecutive zeros.
		for srcIdx >= 8 && binary.LittleEndian.Uint64(src[srcIdx-8:]) == 0x0000000000000000 {
			binary.LittleEndian.PutUint64(dst[dstIdx-8:], 0x0101010101010101)
			dstIdx -= 8
			srcIdx -= 8
		}

		// Emit one or more blocks in reverse.
		numNonZero := srcIdx - (bytes.LastIndexByte(src[:srcIdx], '\x00') + len("\x00"))
		hasZero := srcIdx-numNonZero > 0 && src[srcIdx-numNonZero-1] == '\x00'
		for {
			copyLen := 0
			if numNonZero > 0 {
				copyLen = cmp.Or(numNonZero%254, 254)
			}
			// Since a full block lacks a subsequent zero,
			// we may need to manually inject an empty block if
			// the following source byte is a zero byte.
			if copyLen == 254 && srcIdx < len(src) && src[srcIdx] == '\x00' {
				dst[dstIdx-1] = 0x01
				dstIdx--
			}
			copy(dst[dstIdx-copyLen:dstIdx], src[srcIdx-copyLen:srcIdx])
			dstIdx -= copyLen
			srcIdx -= copyLen
			numNonZero -= copyLen
			dst[dstIdx-1] = byte(copyLen + 1)
			dstIdx -= 1
			if numNonZero == 0 {
				break
			}
		}
		if hasZero {
			srcIdx--
		}
	}

	return dst
}

// numOverhead computes the exact number of overhead bytes
// needed to be added to COBS-encode the src.
// It assumes the optimization where a last empty block is elided
// if it immediately follows a final full block of non-zero bytes.
// The count does not include any trailing null terminator byte.
func numOverhead(src []byte) (n int) {
	n++ // mandatory leading overhead byte
	for len(src) > 0 {
		// Trim leading zeros as they take up no overhead.
		for len(src) >= 8 && binary.LittleEndian.Uint64(src) == 0 {
			src = src[8:]
		}
		for len(src) > 0 && src[0] == 0 {
			src = src[1:]
		}

		// Long runs of non-zero bytes require an overhead byte.
		numNonZero := bytes.IndexByte(src, '\x00')
		if numNonZero < 0 {
			numNonZero = len(src)
		}
		n += numNonZero / 254 // each full group of 254 needs an overhead byte (except last)
		src = src[numNonZero:]
		if numNonZero > 0 && numNonZero%254 == 0 && len(src) == 0 {
			n-- // exact final group of 254 does not need extra overhead byte
		}
	}
	return n
}

var errUnexpectedEOF = errors.New("cobs: unexpected truncation")
var errUnexpectedNull = errors.New("cobs: unexpected null byte")

// AppendDecode appends the decoded bytes of src to the end of dst.
// The COBS-encoded src must not contain the trailing null terminator byte;
// use [TrimNull] to remove the trailing null terminator byte if needed.
// It reports an error if the src contains invalid COBS.
//
// The src and dst buffers may exactly overlap. For example, it is valid to do:
//
//	b, _ = AppendDecode(b[:0], b)
func AppendDecode(dst, src []byte) ([]byte, error) {
	// Unlike AppendEncode, decoding in a forward direction is still safe
	// when dst overlaps with src since the output is guaranteed to always
	// be smaller than the input. Thus, the dst pointer will never run past
	// src pointer and corrupt the input.

	dst = slices.Grow(dst, len(src))
	if len(src) == 0 {
		return dst, errUnexpectedEOF
	}
	for len(src) > 0 {
		// Performance optimization for many zeros.
		// Leave at least one byte afterwards since the following logic
		// expects to find another overhead byte.
		// Also, the very last overhead byte does not emit a zero.
		for len(src) > 8 && binary.LittleEndian.Uint64(src) == 0x0101010101010101 {
			dst = binary.LittleEndian.AppendUint64(dst, 0x0000000000000000)
			src = src[8:]
		}

		switch n := src[0]; {
		case int(n) > len(src):
			return dst, errUnexpectedEOF
		case n == '\x00' || bytes.IndexByte(src[1:n], '\x00') >= 0:
			return dst, errUnexpectedNull
		default:
			dst = append(dst, src[1:n]...)
			if n-1 < 254 {
				dst = append(dst, 0)
			}
			src = src[n:]
		}
	}
	return TrimNull(dst), nil // trim implicit trailing null byte
}

// AppendNull appends a trailing null terminator byte if it does not already exist.
func AppendNull(dst []byte) []byte {
	if len(dst) > 0 && dst[len(dst)-len("\x00")] == '\x00' {
		return dst
	}
	return append(dst, '\x00')
}

// TrimNull removes a trailing null terminator byte if it exists.
func TrimNull(dst []byte) []byte {
	if len(dst) > 0 && dst[len(dst)-len("\x00")] == '\x00' {
		return dst[:len(dst)-len("\x00")]
	}
	return dst
}
