// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"bytes"
	"testing"
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

	// Test decoding with CLI prefix: 'nlpub:' => 'tlpub:'
	decodedPub = NLPublic{}
	if err := decodedPub.UnmarshalText([]byte(pub.CLIString())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedPub.k[:], pub.k[:]) {
		t.Error("decoded and generated NLPublic bytes differ (CLI prefix)")
	}
}
