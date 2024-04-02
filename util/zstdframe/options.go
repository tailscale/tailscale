// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package zstdframe

import (
	"math/bits"
	"strconv"
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

type maxDecodedSizeLog2 uint8 // uint8 avoids allocation when storing into interface

func (maxDecodedSizeLog2) isOption() {}

// MaxDecodedSize specifies the maximum decoded size and
// is used to protect against hostile content.
// By default, there is no limit.
// This option is ignored when encoding.
func MaxDecodedSize(maxSize uint64) Option {
	if bits.OnesCount64(maxSize) == 1 {
		return maxDecodedSizeLog2(log2(maxSize))
	}
	return maxDecodedSize(maxSize)
}

type maxWindowSizeLog2 uint8 // uint8 avoids allocation when storing into interface

func (maxWindowSizeLog2) isOption() {}

// MaxWindowSize specifies the maximum window size, which must be a power-of-two
// and be in the range of [[zstd.MinWindowSize], [zstd.MaxWindowSize]].
//
// The compression or decompression algorithm will use a LZ77 rolling window
// no larger than the specified size. The compression ratio will be
// adversely affected, but memory requirements will be lower.
// When decompressing, an error is reported if a LZ77 back reference exceeds
// the specified maximum window size.
//
// For decompression, [MaxDecodedSize] is generally more useful.
func MaxWindowSize(maxSize uint64) Option {
	switch {
	case maxSize < zstd.MinWindowSize:
		panic("maximum window size cannot be less than " + strconv.FormatUint(zstd.MinWindowSize, 10))
	case bits.OnesCount64(maxSize) != 1:
		panic("maximum window size must be a power-of-two")
	case maxSize > zstd.MaxWindowSize:
		panic("maximum window size cannot be greater than " + strconv.FormatUint(zstd.MaxWindowSize, 10))
	default:
		return maxWindowSizeLog2(log2(maxSize))
	}
}

type lowMemory bool

func (lowMemory) isOption() {}

// LowMemory specifies that the encoder and decoder should aim to use
// lower amounts of memory at the cost of speed.
// By default, more memory used for better speed.
func LowMemory(low bool) Option { return lowMemory(low) }

var encoderPools sync.Map // map[encoderOptions]*sync.Pool -> *zstd.Encoder

type encoderOptions struct {
	level         zstd.EncoderLevel
	maxWindowLog2 uint8
	checksum      bool
	lowMemory     bool
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
		case maxWindowSizeLog2:
			eopts.maxWindowLog2 = uint8(opt)
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
		var noopts int
		zopts := [...]zstd.EOption{
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
			zstd.WithLowerEncoderMem(eopts.lowMemory),
			nil, // reserved for zstd.WithWindowSize
		}
		if eopts.maxWindowLog2 > 0 {
			zopts[len(zopts)-noopts-1] = zstd.WithWindowSize(1 << eopts.maxWindowLog2)
		} else {
			noopts++
		}
		enc = must.Get(zstd.NewWriter(nil, zopts[:len(zopts)-noopts]...))
	}
	return encoder{pool, enc}
}

func putEncoder(e encoder) { e.pool.Put(e.Encoder) }

var decoderPools sync.Map // map[decoderOptions]*sync.Pool -> *zstd.Decoder

type decoderOptions struct {
	maxSizeLog2   uint8
	maxWindowLog2 uint8
	checksum      bool
	lowMemory     bool
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
		case maxDecodedSizeLog2:
			maxSize = 1 << uint8(opt)
			dopts.maxSizeLog2 = uint8(opt)
		case maxDecodedSize:
			maxSize = uint64(opt)
			dopts.maxSizeLog2 = uint8(log2(maxSize))
		case maxWindowSizeLog2:
			dopts.maxWindowLog2 = uint8(opt)
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
		var noopts int
		zopts := [...]zstd.DOption{
			// Set concurrency=1 to ensure synchronous operation.
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderMaxMemory(1 << min(max(10, dopts.maxSizeLog2), 63)),
			zstd.IgnoreChecksum(!dopts.checksum),
			zstd.WithDecoderLowmem(dopts.lowMemory),
			nil, // reserved for zstd.WithDecoderMaxWindow
		}
		if dopts.maxWindowLog2 > 0 {
			zopts[len(zopts)-noopts-1] = zstd.WithDecoderMaxWindow(1 << dopts.maxWindowLog2)
		} else {
			noopts++
		}
		dec = must.Get(zstd.NewReader(nil, zopts[:len(zopts)-noopts]...))
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

// log2 computes log2 of x rounded up to the nearest integer.
func log2(x uint64) int { return 64 - bits.LeadingZeros64(x-1) }
