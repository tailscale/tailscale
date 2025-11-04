// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDiscoKey(t *testing.T) {
	k := NewDisco()
	if k.IsZero() {
		t.Fatal("DiscoPrivate should not be zero")
	}

	p := k.Public()
	if p.IsZero() {
		t.Fatal("DiscoPublic should not be zero")
	}

	bs, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(bs, []byte("discokey:")) {
		t.Fatalf("serialization of public discokey %s has wrong prefix", p)
	}

	z := DiscoPublic{}
	if !z.IsZero() {
		t.Fatal("IsZero(DiscoPublic{}) is false")
	}
	if s := z.ShortString(); s != "" {
		t.Fatalf("DiscoPublic{}.ShortString() is %q, want \"\"", s)
	}
}

func TestDiscoSerialization(t *testing.T) {
	serialized := `{
      "Pub":"discokey:50d20b455ecf12bc453f83c2cfdb2a24925d06cf2598dcaa54e91af82ce9f765"
    }`

	pub := DiscoPublic{
		k: [32]uint8{
			0x50, 0xd2, 0xb, 0x45, 0x5e, 0xcf, 0x12, 0xbc, 0x45, 0x3f, 0x83,
			0xc2, 0xcf, 0xdb, 0x2a, 0x24, 0x92, 0x5d, 0x6, 0xcf, 0x25, 0x98,
			0xdc, 0xaa, 0x54, 0xe9, 0x1a, 0xf8, 0x2c, 0xe9, 0xf7, 0x65,
		},
	}

	type key struct {
		Pub DiscoPublic
	}

	var a key
	if err := json.Unmarshal([]byte(serialized), &a); err != nil {
		t.Fatal(err)
	}
	if a.Pub != pub {
		t.Errorf("wrong deserialization of public key, got %#v want %#v", a.Pub, pub)
	}

	bs, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	var b bytes.Buffer
	json.Indent(&b, []byte(serialized), "", "  ")
	if got, want := string(bs), b.String(); got != want {
		t.Error("json serialization doesn't roundtrip")
	}
}

func TestDiscoShared(t *testing.T) {
	k1, k2 := NewDisco(), NewDisco()
	s1, s2 := k1.Shared(k2.Public()), k2.Shared(k1.Public())
	if !s1.Equal(s2) {
		t.Error("k1.Shared(k2) != k2.Shared(k1)")
	}
}

func TestSortedPairOfDiscoPublic(t *testing.T) {
	pubA := DiscoPublic{}
	pubA.k[0] = 0x01
	pubB := DiscoPublic{}
	pubB.k[0] = 0x02
	sortedInput := NewSortedPairOfDiscoPublic(pubA, pubB)
	unsortedInput := NewSortedPairOfDiscoPublic(pubB, pubA)
	if sortedInput.Get() != unsortedInput.Get() {
		t.Fatal("sortedInput.Get() != unsortedInput.Get()")
	}
	if unsortedInput.Get()[0] != pubA {
		t.Fatal("unsortedInput.Get()[0] != pubA")
	}
	if unsortedInput.Get()[1] != pubB {
		t.Fatal("unsortedInput.Get()[1] != pubB")
	}
}

func TestDiscoKeyType(t *testing.T) {
	dk := NewDiscoKey()
	if dk == nil {
		t.Fatal("NewDiscoKey returned nil")
	}

	private := dk.Private()
	public := dk.Public()
	short := dk.Short()

	if private.IsZero() {
		t.Fatal("DiscoKey private key should not be zero")
	}
	if public.IsZero() {
		t.Fatal("DiscoKey public key should not be zero")
	}
	if short == "" {
		t.Fatal("DiscoKey short string should not be empty")
	}

	if public != private.Public() {
		t.Fatal("DiscoKey public key doesn't match private key")
	}
	if short != public.ShortString() {
		t.Fatal("DiscoKey short string doesn't match public key")
	}

	gotPrivate, gotPublic := dk.Pair()
	if !gotPrivate.Equal(private) {
		t.Fatal("Pair() returned different private key")
	}
	if gotPublic != public {
		t.Fatal("Pair() returned different public key")
	}
}

func TestDiscoKeyFromPrivate(t *testing.T) {
	originalPrivate := NewDisco()
	dk := NewDiscoKeyFromPrivate(originalPrivate)

	private := dk.Private()
	public := dk.Public()

	if !private.Equal(originalPrivate) {
		t.Fatal("DiscoKey private key doesn't match original")
	}
	if public != originalPrivate.Public() {
		t.Fatal("DiscoKey public key doesn't match derived from original private")
	}
}

func TestDiscoKeySet(t *testing.T) {
	dk := NewDiscoKey()
	oldPrivate := dk.Private()
	oldPublic := dk.Public()

	newPrivate := NewDisco()
	dk.Set(newPrivate)

	currentPrivate := dk.Private()
	currentPublic := dk.Public()

	if currentPrivate.Equal(oldPrivate) {
		t.Fatal("DiscoKey private key should have changed after Set")
	}
	if currentPublic == oldPublic {
		t.Fatal("DiscoKey public key should have changed after Set")
	}
	if !currentPrivate.Equal(newPrivate) {
		t.Fatal("DiscoKey private key doesn't match the set key")
	}
	if currentPublic != newPrivate.Public() {
		t.Fatal("DiscoKey public key doesn't match derived from set private key")
	}
}
