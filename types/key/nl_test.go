// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"bytes"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
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

// When we marshal an NLPublic to CBOR, it is serialised as if it
// was a byte slice using `keyasint`.
func TestNLPublicCBOREncoding(t *testing.T) {
	keyBytes := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	k1 := NLPublic{k: keyBytes}
	k2 := keyBytes[:]

	type NLPublicWrapper struct {
		Public NLPublic `cbor:"1,keyasint"`
	}

	type RawBytesWrapper struct {
		Public []byte `cbor:"1,keyasint"`
	}

	out1, err := cbor.Marshal(NLPublicWrapper{Public: k1})
	if err != nil {
		t.Errorf("marshal k1: %v", err)
	}

	out2, err := cbor.Marshal(RawBytesWrapper{Public: k2})
	if err != nil {
		t.Errorf("marshal k2: %v", err)
	}

	if diff := cmp.Diff(out1, out2); diff != "" {
		t.Fatalf("did not serialise identically; (+NLPublic,-rawBytes):%v", diff)
	}
}

// We can marshal an NLPublic as CBOR and retrieve it later.
func TestNLPublicCBORRoundTrip(t *testing.T) {
	public := NewNLPrivate().Public()

	type Wrapper struct {
		Public NLPublic `cbor:"1"`
	}

	k := Wrapper{Public: public}

	encoded, err := cbor.Marshal(k)
	if err != nil {
		t.Errorf("marshal: %v", err)
	}

	var got Wrapper
	err = cbor.Unmarshal(encoded, &got)
	if err != nil {
		t.Errorf("unmarshal: %v", err)
	}

	if diff := cmp.Diff(k, got); diff != "" {
		t.Fatalf("did not serialise identically; (+want,-got):%v", diff)
	}
}
