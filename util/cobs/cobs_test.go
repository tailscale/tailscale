// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cobs

import (
	"bytes"
	"encoding/hex"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/util/must"
)

var x = func(s string) []byte { return must.Get(hex.DecodeString(s)) }
var n = func(s string, n int) string { return strings.Repeat(s, n) }
var tests = []struct {
	decoded    []byte
	encoded    []byte
	errDecoded error // non-nil implies that encode tests are skipped
	padEncoded bool  // whether there is a trailing empty block after full block
}{
	{decoded: x(n("00", 1)), encoded: x(n("01", 2))},
	{decoded: x("11" + n("00", 8)), encoded: x("02" + "11" + n("01", 8))},
	{decoded: x("11" + n("00", 8) + "22"), encoded: x("02" + "11" + n("01", 7) + "02" + "22")},
	{decoded: x(n("00", 8) + "11" + n("00", 8)), encoded: x(n("01", 8) + "02" + "11" + n("01", 8))},
	{decoded: x(n("01", 253)), encoded: x("FE" + n("01", 253))},
	{decoded: x(n("01", 254)), encoded: x("FF" + n("01", 254))},
	{decoded: x(n("01", 254)), encoded: x("FF" + n("01", 254) + "01"), padEncoded: true},
	{decoded: x(n("01", 255)), encoded: x("FF" + n("01", 254) + "02" + "01")},
	{decoded: x(n("01", 254) + "00"), encoded: x("FF" + n("01", 254) + "0101")},
	{decoded: x(n("01", 508)), encoded: x("FF" + n("01", 254) + "FF" + n("01", 254))},
	{decoded: x(n("01", 509)), encoded: x("FF" + n("01", 254) + "FF" + n("01", 254) + "02" + "01")},
	{decoded: x(n("01", 253) + "FF"), encoded: x("FF" + n("01", 253) + "FF")},

	// Test examples from https://en.wikipedia.org/wiki/Consistent_Overhead_Byte_Stuffing.
	{decoded: x(""), encoded: x("01")},
	{decoded: x("00"), encoded: x("0101")},
	{decoded: x("01"), encoded: x("0201")},
	{decoded: x("0000"), encoded: x("010101")},
	{decoded: x("001100"), encoded: x("01021101")},
	{decoded: x("11220033"), encoded: x("0311220233")},
	{decoded: x("11223344"), encoded: x("0511223344")},
	{decoded: x("11000000"), encoded: x("0211010101")},
	{decoded: x("010203" + n("FF", 249) + "FDFE"), encoded: x("FF010203" + n("FF", 249) + "FDFE")},
	{decoded: x("010203" + n("FF", 249) + "FDFE"), encoded: x("FF010203" + n("FF", 249) + "FDFE01"), padEncoded: true},
	{decoded: x("000102" + n("FF", 249) + "FCFDFE"), encoded: x("01FF0102" + n("FF", 249) + "FCFDFE")},
	{decoded: x("010203" + n("FF", 249) + "FDFEFF"), encoded: x("FF010203" + n("FF", 249) + "FDFE02FF")},
	{decoded: x("020304" + n("FF", 249) + "FEFF00"), encoded: x("FF020304" + n("FF", 249) + "FEFF0101")},
	{decoded: x("030405" + n("FF", 249) + "FF0001"), encoded: x("FE030405" + n("FF", 249) + "FF0201")},

	// Test boundary conditions of optimization for consecutive zeros.
	{decoded: x(n("00", 7)), encoded: x(n("01", 7) + "01")},
	{decoded: x(n("00", 7) + "FF"), encoded: x(n("01", 7) + "02FF")},
	{decoded: x(n("00", 8)), encoded: x(n("01", 8) + "01")},
	{decoded: x(n("00", 8) + "FF"), encoded: x(n("01", 8) + "02FF")},
	{decoded: x(n("00", 9)), encoded: x(n("01", 9) + "01")},
	{decoded: x(n("00", 9) + "FF"), encoded: x(n("01", 9) + "02FF")},
	{decoded: x(n("00", 15)), encoded: x(n("01", 15) + "01")},
	{decoded: x(n("00", 15) + "FF"), encoded: x(n("01", 15) + "02FF")},
	{decoded: x(n("00", 16)), encoded: x(n("01", 16) + "01")},
	{decoded: x(n("00", 16) + "FF"), encoded: x(n("01", 16) + "02FF")},
	{decoded: x(n("00", 17)), encoded: x(n("01", 17) + "01")},
	{decoded: x(n("00", 17) + "FF"), encoded: x(n("01", 17) + "02FF")},

	// Test detection of invalid COBS-encoded inputs.
	{decoded: x(n("00", 1000)), encoded: x(n("01", 1001))},
	{decoded: x(""), encoded: x(""), errDecoded: errUnexpectedEOF},
	{decoded: x(""), encoded: x("02"), errDecoded: errUnexpectedEOF},
	{decoded: x("0100"), encoded: x("020102"), errDecoded: errUnexpectedEOF},
	{decoded: x(""), encoded: x("0301"), errDecoded: errUnexpectedEOF},
	{decoded: x(""), encoded: x("00"), errDecoded: errUnexpectedNull},
	{decoded: x("00"), encoded: x("0100"), errDecoded: errUnexpectedNull},
	{decoded: x(""), encoded: x("0200"), errDecoded: errUnexpectedNull},
	{decoded: x("0100"), encoded: x("020100"), errDecoded: errUnexpectedNull},
}

func Test(t *testing.T) {
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			t.Run("MaxEncodedLen", func(t *testing.T) {
				if tt.errDecoded != nil || tt.padEncoded {
					t.SkipNow() // padded encodings are not produced by AppendEncode
				}
				got := MaxEncodedLen(len(tt.decoded))
				if got < len(tt.encoded) {
					t.Errorf("MaxEncodedLen(%d) = %d, want >= %d", len(tt.decoded), got, len(tt.encoded))
				}
			})

			t.Run("MinDecodedLen", func(t *testing.T) {
				if tt.errDecoded != nil {
					t.SkipNow()
				}
				got := MinDecodedLen(len(tt.encoded))
				if got > len(tt.decoded) {
					t.Errorf("MinDecodedLen(%d) = %d, want <= %d", len(tt.encoded), got, len(tt.decoded))
				}
			})

			t.Run("numOverhead", func(t *testing.T) {
				if tt.errDecoded != nil {
					t.SkipNow()
				}
				got := numOverhead(tt.decoded)
				if tt.padEncoded {
					got++
				}
				want := len(tt.encoded) - len(tt.decoded)
				if got != want {
					t.Errorf("numOverhead = %d, want %d", got, want)
				}
			})

			t.Run("AppendEncode", func(t *testing.T) {
				if tt.errDecoded != nil {
					t.SkipNow()
				}
				for _, prefix := range []string{"", "prefix"} {
					t.Run("Prefix:"+prefix, func(t *testing.T) {
						for _, overlap := range []bool{false, true} {
							t.Run("Overlap:"+strconv.FormatBool(overlap), func(t *testing.T) {
								dst := []byte(prefix)
								src := tt.decoded
								if overlap {
									dst = append(dst, src...)
									src = dst[len(prefix):]
								}
								dst = AppendEncode(dst[:len(prefix)], src)
								if tt.padEncoded {
									dst = append(dst, 0x01)
								}
								if d := cmp.Diff(dst, append([]byte(prefix), tt.encoded...)); d != "" {
									t.Errorf("AppendEncode mismatch (-got +want):\n%s", d)
								}
							})
						}
					})
				}
			})

			t.Run("AppendDecode", func(t *testing.T) {
				for _, prefix := range []string{"", "prefix"} {
					t.Run("Prefix:"+prefix, func(t *testing.T) {
						for _, overlap := range []bool{false, true} {
							t.Run("Overlap:"+strconv.FormatBool(overlap), func(t *testing.T) {
								dst := []byte(prefix)
								src := tt.encoded
								if overlap {
									dst = append(dst, src...)
									src = dst[len(prefix):]
								}
								dst, err := AppendDecode(dst[:len(prefix)], src)
								if d := cmp.Diff(dst, append([]byte(prefix), tt.decoded...)); d != "" {
									t.Errorf("AppendDecode mismatch (-got +want):\n%s", d)
								}
								if err != tt.errDecoded {
									t.Errorf("AppendDecode error = %v, want %v", err, tt.errDecoded)
								}
							})
						}
					})
				}
			})
		})
	}
}

// encodeNaive is a straightforward translation of COBS from the C code
// in the appendix of the paper by Stuart Cheshire and Mary Baker.
//
// This is used as the reference implementation by fuzzing to ensure
// that [appendEncodeForward] and [appendEncodeReverse] are consistent.
func encodeNaive(src []byte) (dst []byte) {
	codeIdxPrev := len(dst)
	codeIdxCurr := len(dst)
	code := 0x01
	dst = append(dst, 0) // placeholder for first block's code byte

	finishBlock := func() {
		dst[codeIdxCurr] = byte(code)
		codeIdxPrev = codeIdxCurr
		codeIdxCurr = len(dst)
		code = 0x01
		dst = append(dst, 0) // placeholder for next block's code byte
	}

	for _, b := range src {
		if b == 0 {
			finishBlock()
		} else {
			dst = append(dst, b)
			code++
			if code == 0xff {
				finishBlock()
			}
		}
	}
	dst[codeIdxCurr] = byte(code) // final block, no trailing placeholder needed

	// Optional space optimization: We can elide a final empty block
	// if the previous block was a full group of non-zeros.
	// The paper does not implement this part, but this is necessary
	// since [appendEncodeForward] and [appendEncodeReverse] do this.
	if code == 0x01 && dst[codeIdxPrev] == 0xff {
		dst = dst[:len(dst)-1]
	}

	return dst
}

func FuzzRoundtrip(f *testing.F) {
	for _, tt := range tests {
		f.Add(tt.decoded)
	}
	f.Fuzz(func(t *testing.T, wantDecoded []byte) {
		var seed [32]byte
		copy(seed[:], wantDecoded)
		rn := rand.New(rand.NewChaCha8(seed))

		prefixLen := min(rn.IntN(len(wantDecoded)+1), 8)
		gotDecoded := slices.Grow(bytes.Clone(wantDecoded), rn.IntN(numOverhead(wantDecoded[prefixLen:])+1))
		wantEncoded := append(bytes.Clone(wantDecoded[:prefixLen]), encodeNaive(wantDecoded[prefixLen:])...)

		gotEncodedForward := appendEncodeForward(slices.Clip(gotDecoded[:prefixLen]), gotDecoded[prefixLen:])
		if string(gotEncodedForward) != string(wantEncoded) {
			t.Errorf("EncodeForward(%d:%x) = %x, want %x", prefixLen, wantDecoded, gotEncodedForward, wantEncoded)
		}

		gotEncodedReverse := appendEncodeReverse(gotDecoded[:prefixLen], gotDecoded[prefixLen:])
		if string(gotEncodedReverse) != string(wantEncoded) {
			t.Errorf("EncodeReverse(%d:%x) = %x, want %x", prefixLen, wantDecoded, gotEncodedReverse, wantEncoded)
		}

		gotOverhead := numOverhead(wantDecoded[prefixLen:])
		wantOverhead := len(wantEncoded) - len(wantDecoded)
		if gotOverhead != wantOverhead {
			t.Errorf("numOverhead(%x) = %d, want %d", wantDecoded[prefixLen:], gotOverhead, wantOverhead)
		}

		gotDecoded = must.Get(AppendDecode(wantEncoded[:prefixLen], wantEncoded[prefixLen:]))
		if string(gotDecoded) != string(wantDecoded) {
			t.Errorf("Decode(Encode(%d:%x)) != %x", prefixLen, wantDecoded, gotDecoded)
		}
	})
}

func FuzzMostlyBijective(f *testing.F) {
	for _, tt := range tests {
		f.Add(tt.encoded)
	}
	f.Fuzz(func(t *testing.T, wantEncoded []byte) {
		// There is mostly a bijective mapping for the COBS-encoding
		// such that there is exactly only one valid COBS-encoded blob
		// for every possible non-encoded blob.
		// The only exception is a trailing empty block following
		// a full block of non-zeros.
		decoded, err := AppendDecode(nil, wantEncoded) // must never panic
		if err == nil {
			gotEncoded := AppendEncode(nil, decoded)
			if string(gotEncoded) != string(wantEncoded) && string(gotEncoded)+"\x01" != string(wantEncoded) {
				t.Errorf("Encode(Decode(%x)) != %x", wantEncoded, gotEncoded)
			}
		}
	})
}

func Benchmark(b *testing.B) {
	const length = 1 << 20
	out := make([]byte, MaxEncodedLen(length))
	testdata := []struct {
		name    string
		encoded []byte
		decoded []byte
	}{{
		name:    "Zeros",
		decoded: bytes.Repeat([]byte{0x00}, length),
	}, {
		name:    "NonZeros",
		decoded: bytes.Repeat([]byte{0xFF}, length),
	}, {
		name: "Random",
		decoded: func() []byte {
			b := make([]byte, length)
			must.Get(new(rand.ChaCha8).Read(b))
			return b
		}(),
	}}
	for _, tt := range testdata {
		tt.encoded = AppendEncode(nil, tt.decoded)
		if string(must.Get(AppendDecode(out[:0], tt.encoded))) != string(tt.decoded) {
			b.Fatal("Decode(Encode(...)) roundtrip mismatch")
		}
		b.Run("EncodeForward/"+tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(length)
			for b.Loop() {
				out = appendEncodeForward(out[:0], tt.decoded)
			}
		})
		b.Run("EncodeReverse/"+tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(length)
			for b.Loop() {
				out = appendEncodeReverse(out[:0], tt.decoded)
			}
		})
		b.Run("DecodeForward/"+tt.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(length)
			for b.Loop() {
				out = must.Get(AppendDecode(out[:0], tt.encoded))
			}
		})
	}
}
