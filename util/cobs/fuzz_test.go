// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cobs

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"testing"

	"tailscale.com/util/must"
)

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
