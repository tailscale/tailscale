// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"bytes"
	"testing"
)

func TestRand(t *testing.T) {
	var bs [32]byte
	rand(bs[:])
	if bs == [32]byte{} {
		t.Fatal("rand didn't provide randomness")
	}
	var bs2 [32]byte
	rand(bs2[:])
	if bytes.Equal(bs[:], bs2[:]) {
		t.Fatal("rand returned the same data twice")
	}
}

func TestClamp25519Private(t *testing.T) {
	for range 100 {
		var k [32]byte
		rand(k[:])
		clamp25519Private(k[:])
		if k[0]&0b111 != 0 {
			t.Fatalf("Bogus clamping in first byte: %#08b", k[0])
			return
		}
		if k[31]>>6 != 1 {
			t.Fatalf("Bogus clamping in last byte: %#08b", k[0])
		}
	}
}
