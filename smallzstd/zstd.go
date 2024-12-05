// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package smallzstd produces zstd encoders and decoders optimized for
// low memory usage, at the expense of compression efficiency.
//
// This package is optimized primarily for the memory cost of
// compressing and decompressing data. We reduce this cost in two
// major ways: disable parallelism within the library (i.e. don't use
// multiple CPU cores to decompress), and drop the compression window
// down from the defaults of 4-16MiB, to 8kiB.
//
// Decompressors cost 2x the window size in RAM to run, so by using an
// 8kiB window, we can run ~1000 more decompressors per unit of memory
// than with the defaults.
//
// Depending on context, the benefit is either being able to run more
// decoders (e.g. in our logs processing system), or having a lower
// memory footprint when using compression in network protocols
// (e.g. in tailscaled, which should have a minimal RAM cost).
package smallzstd

import (
	"io"

	"github.com/klauspost/compress/zstd"
)

// WindowSize is the window size used for zstd compression. Decoder
// memory usage scales linearly with WindowSize.
const WindowSize = 8 << 10 // 8kiB

// NewDecoder returns a zstd.Decoder configured for low memory usage,
// at the expense of decompression performance.
func NewDecoder(r io.Reader, options ...zstd.DOption) (*zstd.Decoder, error) {
	defaults := []zstd.DOption{
		// Default is GOMAXPROCS, which costs many KiB in stacks.
		zstd.WithDecoderConcurrency(1),
		// Default is to allocate more upfront for performance. We
		// prefer lower memory use and a bit of GC load.
		zstd.WithDecoderLowmem(true),
		// You might expect to see zstd.WithDecoderMaxMemory
		// here. However, it's not terribly safe to use if you're
		// doing stateless decoding, because it sets the maximum
		// amount of memory the decompressed data can occupy, rather
		// than the window size of the zstd stream. This means a very
		// compressible piece of data might violate the max memory
		// limit here, even if the window size (and thus total memory
		// required to decompress the data) is small.
		//
		// As a result, we don't set a decoder limit here, and rely on
		// the encoder below producing "cheap" streams. Callers are
		// welcome to set their own max memory setting, if
		// contextually there is a clearly correct value (e.g. it's
		// known from the upper layer protocol that the decoded data
		// can never be more than 1MiB).
	}

	return zstd.NewReader(r, append(defaults, options...)...)
}

// NewEncoder returns a zstd.Encoder configured for low memory usage,
// both during compression and at decompression time, at the expense
// of performance and compression efficiency.
func NewEncoder(w io.Writer, options ...zstd.EOption) (*zstd.Encoder, error) {
	defaults := []zstd.EOption{
		// Default is GOMAXPROCS, which costs many KiB in stacks.
		zstd.WithEncoderConcurrency(1),
		// Default is several MiB, which bloats both encoders and
		// their corresponding decoders.
		zstd.WithWindowSize(WindowSize),
		// Encode zero-length inputs in a way that the `zstd` utility
		// can read, because interoperability is handy.
		zstd.WithZeroFrames(true),
	}

	return zstd.NewWriter(w, append(defaults, options...)...)
}
