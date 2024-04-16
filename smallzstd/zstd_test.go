// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package smallzstd

import (
	"os"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func BenchmarkSmallEncoder(b *testing.B) {
	benchEncoder(b, func() (*zstd.Encoder, error) { return NewEncoder(nil) })
}

func BenchmarkSmallEncoderWithBuild(b *testing.B) {
	benchEncoderWithConstruction(b, func() (*zstd.Encoder, error) { return NewEncoder(nil) })
}

func BenchmarkStockEncoder(b *testing.B) {
	benchEncoder(b, func() (*zstd.Encoder, error) { return zstd.NewWriter(nil) })
}

func BenchmarkStockEncoderWithBuild(b *testing.B) {
	benchEncoderWithConstruction(b, func() (*zstd.Encoder, error) { return zstd.NewWriter(nil) })
}

func BenchmarkSmallDecoder(b *testing.B) {
	benchDecoder(b, func() (*zstd.Decoder, error) { return NewDecoder(nil) })
}

func BenchmarkSmallDecoderWithBuild(b *testing.B) {
	benchDecoderWithConstruction(b, func() (*zstd.Decoder, error) { return NewDecoder(nil) })
}

func BenchmarkStockDecoder(b *testing.B) {
	benchDecoder(b, func() (*zstd.Decoder, error) { return zstd.NewReader(nil) })
}

func BenchmarkStockDecoderWithBuild(b *testing.B) {
	benchDecoderWithConstruction(b, func() (*zstd.Decoder, error) { return zstd.NewReader(nil) })
}

func benchEncoder(b *testing.B, mk func() (*zstd.Encoder, error)) {
	b.ReportAllocs()

	in := testdata(b)
	out := make([]byte, 0, 10<<10) // 10kiB

	e, err := mk()
	if err != nil {
		b.Fatalf("making encoder: %v", err)
	}

	b.ResetTimer()
	for range b.N {
		e.EncodeAll(in, out)
	}
}

func benchEncoderWithConstruction(b *testing.B, mk func() (*zstd.Encoder, error)) {
	b.ReportAllocs()

	in := testdata(b)
	out := make([]byte, 0, 10<<10) // 10kiB

	b.ResetTimer()
	for range b.N {
		e, err := mk()
		if err != nil {
			b.Fatalf("making encoder: %v", err)
		}

		e.EncodeAll(in, out)
	}
}

func benchDecoder(b *testing.B, mk func() (*zstd.Decoder, error)) {
	b.ReportAllocs()

	in := compressedTestdata(b)
	out := make([]byte, 0, 10<<10)

	d, err := mk()
	if err != nil {
		b.Fatalf("creating decoder: %v", err)
	}

	b.ResetTimer()
	for range b.N {
		d.DecodeAll(in, out)
	}
}

func benchDecoderWithConstruction(b *testing.B, mk func() (*zstd.Decoder, error)) {
	b.ReportAllocs()

	in := compressedTestdata(b)
	out := make([]byte, 0, 10<<10)

	b.ResetTimer()
	for range b.N {
		d, err := mk()
		if err != nil {
			b.Fatalf("creating decoder: %v", err)
		}

		d.DecodeAll(in, out)
	}
}

func testdata(b *testing.B) []byte {
	b.Helper()
	in, err := os.ReadFile("testdata")
	if err != nil {
		b.Fatalf("reading testdata: %v", err)
	}
	return in
}

func compressedTestdata(b *testing.B) []byte {
	b.Helper()
	uncomp := testdata(b)
	e, err := NewEncoder(nil)
	if err != nil {
		b.Fatalf("creating encoder: %v", err)
	}
	return e.EncodeAll(uncomp, nil)
}
