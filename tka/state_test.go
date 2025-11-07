// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tka

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/types/key"
)

func fromHex(in string) []byte {
	out, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}

func hashFromHex(in string) *AUMHash {
	var out AUMHash
	copy(out[:], fromHex(in))
	return &out
}

func TestCloneState(t *testing.T) {
	tcs := []struct {
		Name  string
		State State
	}{
		{
			"Empty",
			State{},
		},
		{
			"Key",
			State{
				Keys: []Key{{Kind: Key25519, Votes: 2, Public: key.NewNLPrivate().Public(), Meta: map[string]string{"a": "b"}}},
			},
		},
		{
			"StateID",
			State{
				StateID1: 42,
				StateID2: 22,
			},
		},
		{
			"DisablementSecrets",
			State{
				DisablementSecrets: [][]byte{
					{1, 2, 3, 4},
					{5, 6, 7, 8},
				},
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			if diff := cmp.Diff(tc.State, tc.State.Clone()); diff != "" {
				t.Errorf("output state differs (-want, +got):\n%s", diff)
			}

			// Make sure the cloned State is the same even after
			// an encode + decode into + from CBOR.
			t.Run("cbor", func(t *testing.T) {
				out := bytes.NewBuffer(nil)
				encoder, err := cbor.CTAP2EncOptions().EncMode()
				if err != nil {
					t.Fatal(err)
				}
				if err := encoder.NewEncoder(out).Encode(tc.State.Clone()); err != nil {
					t.Fatal(err)
				}

				var decodedState State
				if err := cbor.Unmarshal(out.Bytes(), &decodedState); err != nil {
					t.Fatalf("Unmarshal failed: %v", err)
				}
				if diff := cmp.Diff(tc.State, decodedState); diff != "" {
					t.Errorf("decoded state differs (-want, +got):\n%s", diff)
				}
			})
		})
	}
}

func TestApplyUpdatesChain(t *testing.T) {
	pub1 := key.NLPublicFromBytes(bytes.Repeat([]byte{0x01}, 32))
	pub2 := key.NLPublicFromBytes(bytes.Repeat([]byte{0x02}, 32))
	intOne := uint(1)
	tcs := []struct {
		Name    string
		Updates []AUM
		Start   State
		End     State
	}{
		{
			Name:    "AddKey",
			Updates: []AUM{{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: pub1}}},
			Start:   State{},
			End: State{
				Keys:        []Key{{Kind: Key25519, Public: pub1}},
				LastAUMHash: hashFromHex("7809514b61a986843879bde59d974cce140e1c93853366b6b36e3bdd74f8fe8f"),
			},
		},
		{
			Name:    "RemoveKey",
			Updates: []AUM{{MessageKind: AUMRemoveKey, KeyID: pub1.KeyID(), PrevAUMHash: fromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03")}},
			Start: State{
				Keys:        []Key{{Kind: Key25519, Public: pub1}},
				LastAUMHash: hashFromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03"),
			},
			End: State{
				LastAUMHash: hashFromHex("f82f91bf907ad85eb33fbadfa2d65362031fea572c4535a3fd8b8fca8a352f65"),
			},
		},
		{
			Name:    "UpdateKey",
			Updates: []AUM{{MessageKind: AUMUpdateKey, KeyID: pub1.KeyID(), Votes: &intOne, Meta: map[string]string{"a": "b"}, PrevAUMHash: fromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03")}},
			Start: State{
				Keys:        []Key{{Kind: Key25519, Public: pub1}},
				LastAUMHash: hashFromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03"),
			},
			End: State{
				LastAUMHash: hashFromHex("c37e47588843a7c6ae98e737bac40aa554b6c7467e0fb01d5d7ed5181a21597d"),
				Keys:        []Key{{Kind: Key25519, Votes: 1, Meta: map[string]string{"a": "b"}, Public: pub1}},
			},
		},
		{
			Name: "ChainedKeyUpdates",
			Updates: []AUM{
				{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: pub2}},
				{MessageKind: AUMRemoveKey, KeyID: pub1.KeyID(), PrevAUMHash: fromHex("881962b6491b58169b027b681fd76053c01b89f877749482d3ef54668f62c8bc")},
			},
			Start: State{
				Keys: []Key{{Kind: Key25519, Public: pub1}},
			},
			End: State{
				Keys:        []Key{{Kind: Key25519, Public: pub2}},
				LastAUMHash: hashFromHex("f46fff97566919188d289b6b9e1c81c425aae928b677dfdc4fcd5ba2fc09e2e2"),
			},
		},
		{
			Name: "Checkpoint",
			Updates: []AUM{
				{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: pub2}},
				{MessageKind: AUMCheckpoint, State: &State{
					Keys: []Key{{Kind: Key25519, Public: pub1}},
				}, PrevAUMHash: fromHex("881962b6491b58169b027b681fd76053c01b89f877749482d3ef54668f62c8bc")},
			},
			Start: State{DisablementSecrets: [][]byte{{1, 2, 3, 4}}},
			End: State{
				Keys:        []Key{{Kind: Key25519, Public: pub1}},
				LastAUMHash: hashFromHex("6a66117fd82728cc36e08517df721a58beda86b81cf0c91c078402673c44fcce"),
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			state := tc.Start
			for i := range tc.Updates {
				var err error
				// t.Logf("update[%d] start-state = %+v", i, state)
				state, err = state.applyVerifiedAUM(tc.Updates[i])
				if err != nil {
					t.Fatalf("Apply message[%d] failed: %v", i, err)
				}
				// t.Logf("update[%d] end-state = %+v", i, state)

				updateHash := tc.Updates[i].Hash()
				if got, want := *state.LastAUMHash, updateHash[:]; !bytes.Equal(got[:], want) {
					t.Errorf("expected state.LastAUMHash = %x (update %d), got %x", want, i, got)
				}
			}

			if diff := cmp.Diff(tc.End, state, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("output state differs (+got, -want):\n%s", diff)
			}
		})
	}
}

func TestApplyUpdateErrors(t *testing.T) {
	pub1, _ := testingNLKey(t)
	pub2, _ := testingNLKey(t)
	tooLargeVotes := uint(99999)
	tcs := []struct {
		Name    string
		Updates []AUM
		Start   State
		Error   error
	}{
		{
			"AddKey exists",
			[]AUM{{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: pub1}}},
			State{Keys: []Key{{Kind: Key25519, Public: pub1}}},
			errors.New("key already exists"),
		},
		{
			"RemoveKey notfound",
			[]AUM{{MessageKind: AUMRemoveKey, Key: &Key{Kind: Key25519, Public: pub1}}},
			State{},
			ErrNoSuchKey,
		},
		{
			"UpdateKey notfound",
			[]AUM{{MessageKind: AUMUpdateKey, KeyID: []byte{1}}},
			State{},
			ErrNoSuchKey,
		},
		{
			"UpdateKey now fails validation",
			[]AUM{{MessageKind: AUMUpdateKey, KeyID: pub1.KeyID(), Votes: &tooLargeVotes}},
			State{Keys: []Key{{Kind: Key25519, Public: pub1}}},
			errors.New("updated key fails validation: excessive key weight: 99999 > 4096"),
		},
		{
			"Bad lastAUMHash",
			[]AUM{
				{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: pub2}},
				{MessageKind: AUMRemoveKey, KeyID: pub1.KeyID(), PrevAUMHash: fromHex("1234")},
			},
			State{
				Keys: []Key{{Kind: Key25519, Public: pub1}},
			},
			errors.New("parent AUMHash mismatch"),
		},
		{
			"Bad StateID",
			[]AUM{{MessageKind: AUMCheckpoint, State: &State{StateID1: 1}}},
			State{Keys: []Key{{Kind: Key25519, Public: pub1}}, StateID1: 42},
			errors.New("checkpointed state has an incorrect stateID"),
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			state := tc.Start
			for i := range tc.Updates {
				var err error
				// t.Logf("update[%d] start-state = %+v", i, state)
				state, err = state.applyVerifiedAUM(tc.Updates[i])
				if err != nil {
					if err.Error() != tc.Error.Error() {
						t.Errorf("state[%d].Err = %v, want %v", i, err, tc.Error)
					} else {
						return
					}
				}
				// t.Logf("update[%d] end-state = %+v", i, state)
			}

			t.Errorf("did not error, expected %v", tc.Error)
		})
	}
}
