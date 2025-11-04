// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"testing"

	"tailscale.com/types/key"
)

func TestDiscoAtomic(t *testing.T) {
	var dk discoAtomic
	dk.Set(key.NewDisco())

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

func TestDiscoAtomicSet(t *testing.T) {
	var dk discoAtomic
	dk.Set(key.NewDisco())
	oldPrivate := dk.Private()
	oldPublic := dk.Public()

	newPrivate := key.NewDisco()
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
