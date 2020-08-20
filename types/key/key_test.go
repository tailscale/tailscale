// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package key

import (
	"testing"

	"github.com/tailscale/wireguard-go/wgcfg"
)

func TestTextUnmarshal(t *testing.T) {
	p := Public{1, 2}
	text, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var p2 Public
	if err := p2.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}
	if p != p2 {
		t.Fatalf("mismatch; got %x want %x", p2, p)
	}
}

func TestClamping(t *testing.T) {
	t.Run("NewPrivate", func(t *testing.T) { testClamping(t, NewPrivate) })

	// Also test the wgcfg package, as their behavior should match.
	t.Run("wgcfg", func(t *testing.T) {
		testClamping(t, func() Private {
			k, err := wgcfg.NewPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			return Private(k)
		})
	})
}

func testClamping(t *testing.T, newKey func() Private) {
	for i := 0; i < 100; i++ {
		k := newKey()
		if k[0]&0b111 != 0 {
			t.Fatalf("Bogus clamping in first byte: %#08b", k[0])
			return
		}
		if k[31]>>6 != 1 {
			t.Fatalf("Bogus clamping in last byte: %#08b", k[0])
		}
	}
}
