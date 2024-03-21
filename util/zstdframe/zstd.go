// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package zstdframe provides functionality for encoding and decoding
// independently compressed zstandard frames.
package zstdframe

import (
	"encoding/binary"
	"io"

	"github.com/klauspost/compress/zstd"
)

// The Go zstd API surface is not ergonomic:
//
//   - Options are set via NewReader and NewWriter and immutable once set.
//
//   - Stateless operations like EncodeAll and DecodeAll are methods on
//     the Encoder and Decoder types, which implies that options cannot be
//     changed without allocating an entirely new Encoder or Decoder.
//
//     This is further strange as Encoder and Decoder types are either
//     stateful or stateless objects depending on semantic context.
//
//   - By default, the zstd package tries to be overly clever by spawning off
//     multiple goroutines to do work, which can lead to both excessive fanout
//     of resources and also subtle race conditions. Also, each Encoder/Decoder
//     never relinquish resources, which makes it unsuitable for lower memory.
//     We work around the zstd defaults by setting concurrency=1 on each coder
//     and pool individual coders, allowing the Go GC to reclaim unused coders.
//
//     See https://github.com/klauspost/compress/issues/264
//     See https://github.com/klauspost/compress/issues/479
//
//   - The EncodeAll and DecodeAll functions appends to a user-provided buffer,
//     but uses a signature opposite of most append-like functions in Go,
//     where the output buffer is the second argument, leading to footguns.
//     The zstdframe package provides AppendEncode and AppendDecode functions
//     that follows Go convention of the first argument being the output buffer
//     similar to how the builtin append function operates.
//
//     See https://github.com/klauspost/compress/issues/648
//
//   - The zstd package is oddly inconsistent about naming. For example,
//     IgnoreChecksum vs WithEncoderCRC, or
//     WithDecoderLowmem vs WithLowerEncoderMem.
//     Most options have a WithDecoder or WithEncoder prefix, but some do not.
//
// The zstdframe package wraps the zstd package and presents a more ergonomic API
// by providing stateless functions that take in variadic options.
// Pooling of resources is handled by this package to avoid each caller
// redundantly performing the same pooling at different call sites.

// TODO: Since compression is CPU bound,
// should we have a semaphore ensure at most one operation per CPU?

// AppendEncode appends the zstandard encoded content of src to dst.
// It emits exactly one frame as a single segment.
func AppendEncode(dst, src []byte, opts ...Option) []byte {
	enc := getEncoder(opts...)
	defer putEncoder(enc)
	return enc.EncodeAll(src, dst)
}

// AppendDecode appends the zstandard decoded content of src to dst.
// The input may consist of zero or more frames.
// Any call that handles untrusted input should specify [MaxDecodedSize].
func AppendDecode(dst, src []byte, opts ...Option) ([]byte, error) {
	dec := getDecoder(opts...)
	defer putDecoder(dec)
	return dec.DecodeAll(src, dst)
}

// NextSize parses the next frame (regardless of whether it is a
// data frame or a metadata frame) and returns the total size of the frame.
// The frame can be skipped by slicing n bytes from b (e.g., b[n:]).
// It report [io.ErrUnexpectedEOF] if the frame is incomplete.
func NextSize(b []byte) (n int, err error) {
	// Parse the frame header (RFC 8878, section 3.1.1.).
	var frame zstd.Header
	if err := frame.Decode(b); err != nil {
		return n, err
	}
	n += frame.HeaderSize

	if frame.Skippable {
		// Handle skippable frame (RFC 8878, section 3.1.2.).
		if len(b[n:]) < int(frame.SkippableSize) {
			return n, io.ErrUnexpectedEOF
		}
		n += int(frame.SkippableSize)
	} else {
		// Handle one or more Data_Blocks (RFC 8878, section 3.1.1.2.).
		for {
			if len(b[n:]) < 3 {
				return n, io.ErrUnexpectedEOF
			}
			blockHeader := binary.LittleEndian.Uint32(b[n-1:]) >> 8 // load uint24
			lastBlock := (blockHeader >> 0) & ((1 << 1) - 1)
			blockType := (blockHeader >> 1) & ((1 << 2) - 1)
			blockSize := (blockHeader >> 3) & ((1 << 21) - 1)
			n += 3
			if blockType == 1 {
				// For RLE_Block (RFC 8878, section 3.1.1.2.2.),
				// the Block_Content is only a single byte.
				blockSize = 1
			}
			if len(b[n:]) < int(blockSize) {
				return n, io.ErrUnexpectedEOF
			}
			n += int(blockSize)
			if lastBlock != 0 {
				break
			}
		}

		// Handle optional Content_Checksum (RFC 8878, section 3.1.1.).
		if frame.HasCheckSum {
			if len(b[n:]) < 4 {
				return n, io.ErrUnexpectedEOF
			}
			n += 4
		}
	}
	return n, nil
}
