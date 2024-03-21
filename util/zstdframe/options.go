// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package zstdframe

import (
	"math/bits"
	"sync"

	"github.com/klauspost/compress/zstd"
	"tailscale.com/util/must"
)

// Option is an option that can be passed to [AppendEncode] or [AppendDecode].
type Option interface{ isOption() }

type encoderLevel int

// Constants that implement [Option] and can be passed to [AppendEncode].
const (
	FastestCompression = encoderLevel(zstd.SpeedFastest)
	DefaultCompression = encoderLevel(zstd.SpeedDefault)
	BetterCompression  = encoderLevel(zstd.SpeedBetterCompression)
	BestCompression    = encoderLevel(zstd.SpeedBestCompression)
)

func (encoderLevel) isOption() {}

// EncoderLevel specifies the compression level when encoding.
//
// This exists for compatibility with [zstd.EncoderLevel] values.
// Most usages should directly use one of the following constants:
//   - [FastestCompression]
//   - [DefaultCompression]
//   - [BetterCompression]
//   - [BestCompression]
//
// By default, [DefaultCompression] is chosen.
// This option is ignored when decoding.
func EncoderLevel(level zstd.EncoderLevel) Option { return encoderLevel(level) }

type withChecksum bool

func (withChecksum) isOption() {}

// WithChecksum specifies whether to produce a checksum when encoding,
// or whether to verify the checksum when decoding.
// By default, checksums are produced and verified.
func WithChecksum(check bool) Option { return withChecksum(check) }

type maxDecodedSize uint64

func (maxDecodedSize) isOption() {}

// MaxDecodedSize specifies the maximum decoded size and
// is used to protect against hostile content.
// By default, there is no limit.
// This option is ignored when encoding.
func MaxDecodedSize(maxSize uint64) Option {
	return maxDecodedSize(maxSize)
}

type lowMemory bool

func (lowMemory) isOption() {}

// LowMemory specifies that the encoder and decoder should aim to use
// lower amounts of memory at the cost of speed.
// By default, more memory used for better speed.
func LowMemory(low bool) Option { return lowMemory(low) }

var encoderPools sync.Map // map[encoderOptions]*sync.Pool -> *zstd.Encoder

type encoderOptions struct {
	level     zstd.EncoderLevel
	checksum  bool
	lowMemory bool
}

type encoder struct {
	pool *sync.Pool
	*zstd.Encoder
}

func getEncoder(opts ...Option) encoder {
	eopts := encoderOptions{level: zstd.SpeedDefault, checksum: true}
	for _, opt := range opts {
		switch opt := opt.(type) {
		case encoderLevel:
			eopts.level = zstd.EncoderLevel(opt)
		case withChecksum:
			eopts.checksum = bool(opt)
		case lowMemory:
			eopts.lowMemory = bool(opt)
		}
	}

	vpool, ok := encoderPools.Load(eopts)
	if !ok {
		vpool, _ = encoderPools.LoadOrStore(eopts, new(sync.Pool))
	}
	pool := vpool.(*sync.Pool)
	enc, _ := pool.Get().(*zstd.Encoder)
	if enc == nil {
		enc = must.Get(zstd.NewWriter(nil,
			// Set concurrency=1 to ensure synchronous operation.
			zstd.WithEncoderConcurrency(1),
			// In stateless compression, the data is already in a single buffer,
			// so we might as well encode it as a single segment,
			// which ensures that the Frame_Content_Size is always populated,
			// informing decoders up-front the expected decompressed size.
			zstd.WithSingleSegment(true),
			// Ensure strict compliance with RFC 8878, section 3.1.,
			// where zstandard "is made up of one or more frames".
			zstd.WithZeroFrames(true),
			zstd.WithEncoderLevel(eopts.level),
			zstd.WithEncoderCRC(eopts.checksum),
			zstd.WithLowerEncoderMem(eopts.lowMemory)))
	}
	return encoder{pool, enc}
}

func putEncoder(e encoder) { e.pool.Put(e.Encoder) }

var decoderPools sync.Map // map[decoderOptions]*sync.Pool -> *zstd.Decoder

type decoderOptions struct {
	maxSizeLog2 int
	checksum    bool
	lowMemory   bool
}

type decoder struct {
	pool *sync.Pool
	*zstd.Decoder

	maxSize uint64
}

func getDecoder(opts ...Option) decoder {
	maxSize := uint64(1 << 63)
	dopts := decoderOptions{maxSizeLog2: 63, checksum: true}
	for _, opt := range opts {
		switch opt := opt.(type) {
		case maxDecodedSize:
			maxSize = uint64(opt)
			dopts.maxSizeLog2 = 64 - bits.LeadingZeros64(maxSize-1)
			dopts.maxSizeLog2 = min(max(10, dopts.maxSizeLog2), 63)
		case withChecksum:
			dopts.checksum = bool(opt)
		case lowMemory:
			dopts.lowMemory = bool(opt)
		}
	}

	vpool, ok := decoderPools.Load(dopts)
	if !ok {
		vpool, _ = decoderPools.LoadOrStore(dopts, new(sync.Pool))
	}
	pool := vpool.(*sync.Pool)
	dec, _ := pool.Get().(*zstd.Decoder)
	if dec == nil {
		dec = must.Get(zstd.NewReader(nil,
			// Set concurrency=1 to ensure synchronous operation.
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(1<<dopts.maxSizeLog2),
			zstd.IgnoreChecksum(!dopts.checksum),
			zstd.WithDecoderLowmem(dopts.lowMemory)))
	}
	return decoder{pool, dec, maxSize}
}

func putDecoder(d decoder) { d.pool.Put(d.Decoder) }

func (d decoder) DecodeAll(src, dst []byte) ([]byte, error) {
	// We only configure DecodeAll to enforce MaxDecodedSize by powers-of-two.
	// Perform a more fine grain check based on the exact value.
	dst2, err := d.Decoder.DecodeAll(src, dst)
	if err == nil && uint64(len(dst2)-len(dst)) > d.maxSize {
		err = zstd.ErrDecoderSizeExceeded
	}
	return dst2, err
}
