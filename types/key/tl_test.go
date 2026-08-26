// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"bytes"
	"testing"
)

func TestTLPrivate(t *testing.T) {
	p := NewTLPrivate()

	encoded, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var decoded TLPrivate
	if err := decoded.UnmarshalText(encoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.k[:], p.k[:]) {
		t.Error("decoded and generated TLPrivate bytes differ")
	}

	// Test TLPublic
	pub := p.Public()
	encoded, err = pub.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var decodedPub TLPublic
	if err := decodedPub.UnmarshalText(encoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedPub.k[:], pub.k[:]) {
		t.Error("decoded and generated TLPublic bytes differ")
	}

	// Test decoding with CLI prefix: 'nlpub:' => 'tlpub:'
	decodedPub = TLPublic{}
	if err := decodedPub.UnmarshalText([]byte(pub.CLIString())); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decodedPub.k[:], pub.k[:]) {
		t.Error("decoded and generated TLPublic bytes differ (CLI prefix)")
	}
}
