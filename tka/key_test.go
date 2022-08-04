// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"math/rand"
	"testing"

	"tailscale.com/types/tkatype"
)

// returns a random source based on the test name + extraSeed.
func testingRand(t *testing.T, extraSeed int64) *rand.Rand {
	var seed int64
	if err := binary.Read(bytes.NewBuffer([]byte(t.Name())), binary.LittleEndian, &seed); err != nil {
		panic(err)
	}
	return rand.New(rand.NewSource(seed + extraSeed))
}

// generates a 25519 private key based on the seed + test name.
func testingKey25519(t *testing.T, seed int64) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(testingRand(t, seed))
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func TestVerify25519(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{
		Kind:   Key25519,
		Public: pub,
	}

	aum := AUM{
		MessageKind: AUMRemoveKey,
		KeyID:       []byte{1, 2, 3, 4},
		// Signatures is set to crap so we are sure its ignored in the sigHash computation.
		Signatures: []tkatype.Signature{{KeyID: []byte{45, 42}}},
	}
	sigHash := aum.SigHash()
	aum.Signatures = []tkatype.Signature{
		{
			KeyID:     key.ID(),
			Signature: ed25519.Sign(priv, sigHash[:]),
		},
	}

	if err := signatureVerify(&aum.Signatures[0], aum.SigHash(), key); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}

	// Make sure it fails with a different public key.
	pub2, _ := testingKey25519(t, 2)
	key2 := Key{Kind: Key25519, Public: pub2}
	if err := signatureVerify(&aum.Signatures[0], aum.SigHash(), key2); err == nil {
		t.Error("signature verification with different key did not fail")
	}
}
