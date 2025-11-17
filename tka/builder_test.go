// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/tkatype"
)

type signer25519 ed25519.PrivateKey

func (s signer25519) SignAUM(sigHash tkatype.AUMSigHash) ([]tkatype.Signature, error) {
	priv := ed25519.PrivateKey(s)
	key := Key{Kind: Key25519, Public: priv.Public().(ed25519.PublicKey)}

	return []tkatype.Signature{{
		KeyID:     key.MustID(),
		Signature: ed25519.Sign(priv, sigHash[:]),
	}}, nil
}

func TestAuthorityBuilderAddKey(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	storage := ChonkMem()
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
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
	updates, err := b.Finalize(storage)
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the new key is there.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	if _, err := a.state.GetKey(key2.MustID()); err != nil {
		t.Errorf("could not read new key: %v", err)
	}
}
func TestAuthorityBuilderMaxKey(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	storage := ChonkMem()
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	for i := 0; i <= maxKeys; i++ {
		pub2, _ := testingKey25519(t, int64(2+i))
		key2 := Key{Kind: Key25519, Public: pub2, Votes: 1}

		b := a.NewUpdater(signer25519(priv))
		err := b.AddKey(key2)
		if i < maxKeys-1 {
			if err != nil {
				t.Fatalf("AddKey(%v) failed: %v", key2, err)
			}
		} else {
			// Too many keys.
			if err == nil {
				t.Fatalf("AddKey(%v) succeeded unexpectedly", key2)
			}
			continue
		}

		updates, err := b.Finalize(storage)
		if err != nil {
			t.Fatalf("Finalize() failed: %v", err)
		}

		if err := a.Inform(storage, updates); err != nil {
			t.Fatalf("could not apply generated updates: %v", err)
		}
		if _, err := a.state.GetKey(key2.MustID()); err != nil {
			t.Errorf("could not read new key: %v", err)
		}
	}
}

func TestAuthorityBuilderRemoveKey(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}
	pub2, _ := testingKey25519(t, 2)
	key2 := Key{Kind: Key25519, Public: pub2, Votes: 1}

	storage := ChonkMem()
	a, _, err := Create(storage, State{
		Keys:               []Key{key, key2},
		DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	b := a.NewUpdater(signer25519(priv))
	if err := b.RemoveKey(key2.MustID()); err != nil {
		t.Fatalf("RemoveKey(%v) failed: %v", key2, err)
	}
	updates, err := b.Finalize(storage)
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the key has been removed.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	if _, err := a.state.GetKey(key2.MustID()); err != ErrNoSuchKey {
		t.Errorf("GetKey(key2).err = %v, want %v", err, ErrNoSuchKey)
	}

	// Check that removing the remaining key errors out.
	b = a.NewUpdater(signer25519(priv))
	if err := b.RemoveKey(key.MustID()); err != nil {
		t.Fatalf("RemoveKey(%v) failed: %v", key, err)
	}
	updates, err = b.Finalize(storage)
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}
	wantErr := "cannot remove the last key"
	if err := a.Inform(storage, updates); err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("expected Inform() to return error %q, got: %v", wantErr, err)
	}
}

func TestAuthorityBuilderSetKeyVote(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	storage := ChonkMem()
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	b := a.NewUpdater(signer25519(priv))
	if err := b.SetKeyVote(key.MustID(), 5); err != nil {
		t.Fatalf("SetKeyVote(%v) failed: %v", key.MustID(), err)
	}
	updates, err := b.Finalize(storage)
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the update is there.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	k, err := a.state.GetKey(key.MustID())
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

	storage := ChonkMem()
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	b := a.NewUpdater(signer25519(priv))
	if err := b.SetKeyMeta(key.MustID(), map[string]string{"b": "c"}); err != nil {
		t.Fatalf("SetKeyMeta(%v) failed: %v", key, err)
	}
	updates, err := b.Finalize(storage)
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the update is there.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	k, err := a.state.GetKey(key.MustID())
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

	storage := ChonkMem()
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
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
	if err := b.SetKeyVote(key2.MustID(), 42); err != nil {
		t.Fatalf("SetKeyVote(%v) failed: %v", key2, err)
	}
	if err := b.RemoveKey(key.MustID()); err != nil {
		t.Fatalf("RemoveKey(%v) failed: %v", key, err)
	}
	updates, err := b.Finalize(storage)
	if err != nil {
		t.Fatalf("Finalize() failed: %v", err)
	}

	// See if the update is valid by applying it to the authority
	// + checking if the update is there.
	if err := a.Inform(storage, updates); err != nil {
		t.Fatalf("could not apply generated updates: %v", err)
	}
	k, err := a.state.GetKey(key2.MustID())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := k.Votes, uint(42); got != want {
		t.Errorf("key.Votes = %d, want %d", got, want)
	}
	if _, err := a.state.GetKey(key.MustID()); err != ErrNoSuchKey {
		t.Errorf("GetKey(key).err = %v, want %v", err, ErrNoSuchKey)
	}
}

func TestAuthorityBuilderCheckpointsAfterXUpdates(t *testing.T) {
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	storage := ChonkMem()
	a, _, err := Create(storage, State{
		Keys:               []Key{key},
		DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
	}, signer25519(priv))
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	for i := 0; i <= checkpointEvery; i++ {
		pub2, _ := testingKey25519(t, int64(i+2))
		key2 := Key{Kind: Key25519, Public: pub2, Votes: 1}

		b := a.NewUpdater(signer25519(priv))
		if err := b.AddKey(key2); err != nil {
			t.Fatalf("AddKey(%v) failed: %v", key2, err)
		}
		updates, err := b.Finalize(storage)
		if err != nil {
			t.Fatalf("Finalize() failed: %v", err)
		}
		// See if the update is valid by applying it to the authority
		// + checking if the new key is there.
		if err := a.Inform(storage, updates); err != nil {
			t.Fatalf("could not apply generated updates: %v", err)
		}
		if _, err := a.state.GetKey(key2.MustID()); err != nil {
			t.Fatal(err)
		}

		wantKind := AUMAddKey
		if i == checkpointEvery-1 { // Genesis + 49 updates == 50 (the value of checkpointEvery)
			wantKind = AUMCheckpoint
		}
		lastAUM, err := storage.AUM(a.Head())
		if err != nil {
			t.Fatal(err)
		}
		if lastAUM.MessageKind != wantKind {
			t.Errorf("[%d] HeadAUM.MessageKind = %v, want %v", i, lastAUM.MessageKind, wantKind)
		}
	}

	// Try starting an authority just based on storage.
	a2, err := Open(storage)
	if err != nil {
		t.Fatalf("Failed to open from stored AUMs: %v", err)
	}
	if a.Head() != a2.Head() {
		t.Errorf("stored and computed HEAD differ: got %v, want %v", a2.Head(), a.Head())
	}
}
