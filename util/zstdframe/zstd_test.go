// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package zstdframe

import (
	"math/bits"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/klauspost/compress/zstd"
	"tailscale.com/util/must"
)

// Use the concatenation of all Go source files in zstdframe as testdata.
var src = func() (out []byte) {
	for _, de := range must.Get(os.ReadDir(".")) {
		if strings.HasSuffix(de.Name(), ".go") {
			out = append(out, must.Get(os.ReadFile(de.Name()))...)
		}
	}
	return out
}()
var dst []byte
var dsts [][]byte

// zstdEnc is identical to getEncoder without options,
// except it relies on concurrency managed by the zstd package itself.
var zstdEnc = must.Get(zstd.NewWriter(nil,
	zstd.WithEncoderConcurrency(runtime.NumCPU()),
	zstd.WithSingleSegment(true),
	zstd.WithZeroFrames(true),
	zstd.WithEncoderLevel(zstd.SpeedDefault),
	zstd.WithEncoderCRC(true),
	zstd.WithLowerEncoderMem(false)))

// zstdDec is identical to getDecoder without options,
// except it relies on concurrency managed by the zstd package itself.
var zstdDec = must.Get(zstd.NewReader(nil,
	zstd.WithDecoderConcurrency(runtime.NumCPU()),
	zstd.WithDecoderMaxMemory(1<<63),
	zstd.IgnoreChecksum(false),
	zstd.WithDecoderLowmem(false)))

var coders = []struct {
	name         string
	appendEncode func([]byte, []byte) []byte
	appendDecode func([]byte, []byte) ([]byte, error)
}{{
	name:         "zstd",
	appendEncode: func(dst, src []byte) []byte { return zstdEnc.EncodeAll(src, dst) },
	appendDecode: func(dst, src []byte) ([]byte, error) { return zstdDec.DecodeAll(src, dst) },
}, {
	name:         "zstdframe",
	appendEncode: func(dst, src []byte) []byte { return AppendEncode(dst, src) },
	appendDecode: func(dst, src []byte) ([]byte, error) { return AppendDecode(dst, src) },
}}

func TestDecodeMaxSize(t *testing.T) {
	var enc, dec []byte
	zeros := make([]byte, 1<<16, 2<<16)
	check := func(encSize, maxDecSize int) {
		var gotErr, wantErr error
		enc = AppendEncode(enc[:0], zeros[:encSize])

		// Directly calling zstd.Decoder.DecodeAll may not trigger size check
		// since it only operates on closest power-of-two.
		dec, gotErr = func() ([]byte, error) {
			d := getDecoder(MaxDecodedSize(uint64(maxDecSize)))
			defer putDecoder(d)
			return d.Decoder.DecodeAll(enc, dec[:0]) // directly call zstd.Decoder.DecodeAll
		}()
		if encSize > 1<<(64-bits.LeadingZeros64(uint64(maxDecSize)-1)) {
			wantErr = zstd.ErrDecoderSizeExceeded
		}
		if gotErr != wantErr {
			t.Errorf("DecodeAll(AppendEncode(%d), %d) error = %v, want %v", encSize, maxDecSize, gotErr, wantErr)
		}

		// Calling AppendDecode should perform the exact size check.
		dec, gotErr = AppendDecode(dec[:0], enc, MaxDecodedSize(uint64(maxDecSize)))
		if encSize > maxDecSize {
			wantErr = zstd.ErrDecoderSizeExceeded
		}
		if gotErr != wantErr {
			t.Errorf("AppendDecode(AppendEncode(%d), %d) error = %v, want %v", encSize, maxDecSize, gotErr, wantErr)
		}
	}

	rn := rand.New(rand.NewPCG(0, 0))
	for n := 1 << 10; n <= len(zeros); n <<= 1 {
		nl := rn.IntN(n + 1)
		check(nl, nl)
		check(nl, nl-1)
		check(nl, (n+nl)/2)
		check(nl, n)
		check((n+nl)/2, n)
		check(n-1, n-1)
		check(n-1, n)
		check(n-1, n+1)
		check(n, n-1)
		check(n, n)
		check(n, n+1)
		check(n+1, n-1)
		check(n+1, n)
		check(n+1, n+1)
	}
}

func BenchmarkEncode(b *testing.B) {
	options := []struct {
		name string
		opts []Option
	}{
		{name: "Best", opts: []Option{BestCompression}},
		{name: "Better", opts: []Option{BetterCompression}},
		{name: "Default", opts: []Option{DefaultCompression}},
		{name: "Fastest", opts: []Option{FastestCompression}},
		{name: "FastestLowMemory", opts: []Option{FastestCompression, LowMemory(true)}},
		{name: "FastestWindowSize", opts: []Option{FastestCompression, MaxWindowSize(1 << 10)}},
		{name: "FastestNoChecksum", opts: []Option{FastestCompression, WithChecksum(false)}},
	}
	for _, bb := range options {
		b.Run(bb.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(src)))
			for range b.N {
				dst = AppendEncode(dst[:0], src, bb.opts...)
			}
		})
		if testing.Verbose() {
			ratio := float64(len(src)) / float64(len(dst))
			b.Logf("ratio:  %0.3fx", ratio)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	options := []struct {
		name string
		opts []Option
	}{
		{name: "Checksum", opts: []Option{WithChecksum(true)}},
		{name: "NoChecksum", opts: []Option{WithChecksum(false)}},
		{name: "LowMemory", opts: []Option{LowMemory(true)}},
	}
	src := AppendEncode(nil, src)
	for _, bb := range options {
		b.Run(bb.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(src)))
			for range b.N {
				dst = must.Get(AppendDecode(dst[:0], src, bb.opts...))
			}
		})
	}
}

func BenchmarkEncodeParallel(b *testing.B) {
	numCPU := runtime.NumCPU()
	for _, coder := range coders {
		dsts = dsts[:0]
		for range numCPU {
			dsts = append(dsts, coder.appendEncode(nil, src))
		}
		b.Run(coder.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				var group sync.WaitGroup
				for j := 0; j < numCPU; j++ {
					group.Add(1)
					go func(j int) {
						defer group.Done()
						dsts[j] = coder.appendEncode(dsts[j][:0], src)
					}(j)
				}
				group.Wait()
			}
		})
	}
}

func BenchmarkDecodeParallel(b *testing.B) {
	numCPU := runtime.NumCPU()
	for _, coder := range coders {
		dsts = dsts[:0]
		src := AppendEncode(nil, src)
		for range numCPU {
			dsts = append(dsts, must.Get(coder.appendDecode(nil, src)))
		}
		b.Run(coder.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				var group sync.WaitGroup
				for j := 0; j < numCPU; j++ {
					group.Add(1)
					go func(j int) {
						defer group.Done()
						dsts[j] = must.Get(coder.appendDecode(dsts[j][:0], src))
					}(j)
				}
				group.Wait()
			}
		})
	}
}

var opt Option

func TestOptionAllocs(t *testing.T) {
	t.Run("EncoderLevel", func(t *testing.T) {
		t.Log(testing.AllocsPerRun(1e3, func() { opt = EncoderLevel(zstd.SpeedFastest) }))
	})
	t.Run("MaxDecodedSize/PowerOfTwo", func(t *testing.T) {
		t.Log(testing.AllocsPerRun(1e3, func() { opt = MaxDecodedSize(1024) }))
	})
	t.Run("MaxDecodedSize/Prime", func(t *testing.T) {
		t.Log(testing.AllocsPerRun(1e3, func() { opt = MaxDecodedSize(1021) }))
	})
	t.Run("MaxWindowSize", func(t *testing.T) {
		t.Log(testing.AllocsPerRun(1e3, func() { opt = MaxWindowSize(1024) }))
	})
	t.Run("LowMemory", func(t *testing.T) {
		t.Log(testing.AllocsPerRun(1e3, func() { opt = LowMemory(true) }))
	})
}

func TestGetDecoderAllocs(t *testing.T) {
	t.Log(testing.AllocsPerRun(1e3, func() { getDecoder() }))
}

func TestGetEncoderAllocs(t *testing.T) {
	t.Log(testing.AllocsPerRun(1e3, func() { getEncoder() }))
}
