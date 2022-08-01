// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package key

import (
	"bytes"
	"testing"

	"tailscale.com/tka"
)

func TestNLPrivate(t *testing.T) {
	p := NewNLPrivate()

	encoded, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var decoded NLPrivate
	if err := decoded.UnmarshalText(encoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.k[:], p.k[:]) {
		t.Error("decoded and generated NLPrivate bytes differ")
	}

	// Test NLPublic
	pub := p.Public()
	encoded, err = pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var decodedPub NLPublic
	if err := decodedPub.UnmarshalText(encoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedPub.k[:], pub.k[:]) {
		t.Error("decoded and generated NLPublic bytes differ")
	}

	// Test that NLPrivate implements tka.Signer by making a new
	// authority.
	k := tka.Key{Kind: tka.Key25519, Public: pub.Verifier(), Votes: 1}
	_, aum, err := tka.Create(&tka.Mem{}, tka.State{
		Keys:               []tka.Key{k},
		DisablementSecrets: [][]byte{bytes.Repeat([]byte{1}, 32)},
	}, p)
	if err != nil {
		t.Fatalf("tka.Create() failed: %v", err)
	}

	// Make sure the generated genesis AUM was signed.
	if got, want := len(aum.Signatures), 1; got != want {
		t.Fatalf("len(signatures) = %d, want %d", got, want)
	}
	if err := aum.Signatures[0].Verify(aum.SigHash(), k); err != nil {
		t.Errorf("signature did not verify: %v", err)
	}
}
