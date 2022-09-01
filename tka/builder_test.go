// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"crypto/ed25519"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/tkatype"
)

type signer25519 ed25519.PrivateKey

func (s signer25519) SignAUM(sigHash tkatype.AUMSigHash) ([]tkatype.Signature, error) {
	priv := ed25519.PrivateKey(s)
	key := Key{Kind: Key25519, Public: priv.Public().(ed25519.PublicKey)}

	return []tkatype.Signature{{
		KeyID:     key.ID(),
		Signature: ed25519.Sign(priv, sigHash[:]),
	}}, nil
}

func TestAuthorityBuilderAddKey(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	storage := &Mem{}
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{disablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	pub2, _ := testingKey25519(t, 2)
	key2 := Key{Kind: Key25519, Public: pub2, Votes: 1}

	b := a.NewUpdater(signer25519(priv))
	if err := b.AddKey(key2); err != nil {
		t.Fatalf("AddKey(%v) failed: %v", key2, err)
	}
	updates, err := b.Finalize()
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the new key is there.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	if _, err := a.state.GetKey(key2.ID()); err != nil {
		t.Errorf("could not read new key: %v", err)
	}
}

func TestAuthorityBuilderRemoveKey(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}
	pub2, _ := testingKey25519(t, 2)
	key2 := Key{Kind: Key25519, Public: pub2, Votes: 1}

	storage := &Mem{}
	a, _, err := Create(storage, State{
		Keys:               []Key{key, key2},
		DisablementSecrets: [][]byte{disablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	b := a.NewUpdater(signer25519(priv))
	if err := b.RemoveKey(key2.ID()); err != nil {
		t.Fatalf("RemoveKey(%v) failed: %v", key2, err)
	}
	updates, err := b.Finalize()
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the key has been removed.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	if _, err := a.state.GetKey(key2.ID()); err != ErrNoSuchKey {
		t.Errorf("GetKey(key2).err = %v, want %v", err, ErrNoSuchKey)
	}
}

func TestAuthorityBuilderSetKeyVote(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	storage := &Mem{}
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{disablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	b := a.NewUpdater(signer25519(priv))
	if err := b.SetKeyVote(key.ID(), 5); err != nil {
		t.Fatalf("SetKeyVote(%v) failed: %v", key.ID(), err)
	}
	updates, err := b.Finalize()
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the update is there.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	k, err := a.state.GetKey(key.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := k.Votes, uint(5); got != want {
		t.Errorf("key.Votes = %d, want %d", got, want)
	}
}

func TestAuthorityBuilderSetKeyMeta(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2, Meta: map[string]string{"a": "b"}}

	storage := &Mem{}
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{disablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	b := a.NewUpdater(signer25519(priv))
	if err := b.SetKeyMeta(key.ID(), map[string]string{"b": "c"}); err != nil {
		t.Fatalf("SetKeyMeta(%v) failed: %v", key, err)
	}
	updates, err := b.Finalize()
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the update is there.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	k, err := a.state.GetKey(key.ID())
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(map[string]string{"b": "c"}, k.Meta); diff != "" {
		t.Errorf("updated meta differs (-want, +got):\n%s", diff)
	}
}

func TestAuthorityBuilderMultiple(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	storage := &Mem{}
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{disablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	pub2, _ := testingKey25519(t, 2)
	key2 := Key{Kind: Key25519, Public: pub2, Votes: 1}

	b := a.NewUpdater(signer25519(priv))
	if err := b.AddKey(key2); err != nil {
		t.Fatalf("AddKey(%v) failed: %v", key2, err)
	}
	if err := b.SetKeyVote(key2.ID(), 42); err != nil {
		t.Fatalf("SetKeyVote(%v) failed: %v", key2, err)
	}
	if err := b.RemoveKey(key.ID()); err != nil {
		t.Fatalf("RemoveKey(%v) failed: %v", key, err)
	}
	updates, err := b.Finalize()
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the update is there.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	k, err := a.state.GetKey(key2.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := k.Votes, uint(42); got != want {
		t.Errorf("key.Votes = %d, want %d", got, want)
	}
	if _, err := a.state.GetKey(key.ID()); err != ErrNoSuchKey {
		t.Errorf("GetKey(key).err = %v, want %v", err, ErrNoSuchKey)
	}
}
