// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgcfg

import (
	"bytes"
	"testing"
)

func TestKeyBasics(t *testing.T) {
	k1, err := NewPresharedKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := k1.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("JSON round-trip", func(t *testing.T) {
		// should preserve the keys
		k2 := new(Key)
		if err := k2.UnmarshalJSON(b); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(k1[:], k2[:]) {
			t.Fatalf("k1 %v != k2 %v", k1[:], k2[:])
		}
		if b1, b2 := k1.String(), k2.String(); b1 != b2 {
			t.Fatalf("base64-encoded keys do not match: %s, %s", b1, b2)
		}
	})

	t.Run("JSON incompatible with PrivateKey", func(t *testing.T) {
		k2 := new(PrivateKey)
		if err := k2.UnmarshalText(b); err == nil {
			t.Fatalf("successfully decoded key as private key")
		}
	})

	t.Run("second key", func(t *testing.T) {
		// A second call to NewPresharedKey should make a new key.
		k3, err := NewPresharedKey()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(k1[:], k3[:]) {
			t.Fatalf("k1 %v == k3 %v", k1[:], k3[:])
		}
		// Check for obvious comparables to make sure we are not generating bad strings somewhere.
		if b1, b2 := k1.String(), k3.String(); b1 == b2 {
			t.Fatalf("base64-encoded keys match: %s, %s", b1, b2)
		}
	})
}
func TestPrivateKeyBasics(t *testing.T) {
	pri, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := pri.MarshalText()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("JSON round-trip", func(t *testing.T) {
		// should preserve the keys
		pri2 := new(PrivateKey)
		if err := pri2.UnmarshalText(b); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pri[:], pri2[:]) {
			t.Fatalf("pri %v != pri2 %v", pri[:], pri2[:])
		}
		if b1, b2 := pri.String(), pri2.String(); b1 != b2 {
			t.Fatalf("base64-encoded keys do not match: %s, %s", b1, b2)
		}
		if pub1, pub2 := pri.Public().String(), pri2.Public().String(); pub1 != pub2 {
			t.Fatalf("base64-encoded public keys do not match: %s, %s", pub1, pub2)
		}
	})

	t.Run("JSON incompatible with Key", func(t *testing.T) {
		k2 := new(Key)
		if err := k2.UnmarshalJSON(b); err == nil {
			t.Fatalf("successfully decoded private key as key")
		}
	})

	t.Run("second key", func(t *testing.T) {
		// A second call to New should make a new key.
		pri3, err := NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(pri[:], pri3[:]) {
			t.Fatalf("pri %v == pri3 %v", pri[:], pri3[:])
		}
		// Check for obvious comparables to make sure we are not generating bad strings somewhere.
		if b1, b2 := pri.String(), pri3.String(); b1 == b2 {
			t.Fatalf("base64-encoded keys match: %s, %s", b1, b2)
		}
		if pub1, pub2 := pri.Public().String(), pri3.Public().String(); pub1 == pub2 {
			t.Fatalf("base64-encoded public keys match: %s, %s", pub1, pub2)
		}
	})
}
