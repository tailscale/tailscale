// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
				Keys: []Key{{Kind: Key25519, Votes: 2, Public: []byte{5, 6, 7, 8}, Meta: map[string]string{"a": "b"}}},
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
	intOne := uint(1)
	tcs := []struct {
		Name    string
		Updates []AUM
		Start   State
		End     State
	}{
		{
			"AddKey",
			[]AUM{{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: []byte{1, 2, 3, 4}}}},
			State{},
			State{
				Keys:        []Key{{Kind: Key25519, Public: []byte{1, 2, 3, 4}}},
				LastAUMHash: hashFromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03"),
			},
		},
		{
			"RemoveKey",
			[]AUM{{MessageKind: AUMRemoveKey, KeyID: []byte{1, 2, 3, 4}, PrevAUMHash: fromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03")}},
			State{
				Keys:        []Key{{Kind: Key25519, Public: []byte{1, 2, 3, 4}}},
				LastAUMHash: hashFromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03"),
			},
			State{
				LastAUMHash: hashFromHex("15d65756abfafbb592279503f40759898590c9c59056be1e2e9f02684c15ba4b"),
			},
		},
		{
			"UpdateKey",
			[]AUM{{MessageKind: AUMUpdateKey, KeyID: []byte{1, 2, 3, 4}, Votes: &intOne, Meta: map[string]string{"a": "b"}, PrevAUMHash: fromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03")}},
			State{
				Keys:        []Key{{Kind: Key25519, Public: []byte{1, 2, 3, 4}}},
				LastAUMHash: hashFromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03"),
			},
			State{
				LastAUMHash: hashFromHex("828fe04c16032cf3e0b021abca0b4d79924b0a18b2e627b308347aa87ce7c21c"),
				Keys:        []Key{{Kind: Key25519, Votes: 1, Meta: map[string]string{"a": "b"}, Public: []byte{1, 2, 3, 4}}},
			},
		},
		{
			"ChainedKeyUpdates",
			[]AUM{
				{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: []byte{5, 6, 7, 8}}},
				{MessageKind: AUMRemoveKey, KeyID: []byte{1, 2, 3, 4}, PrevAUMHash: fromHex("f09bda3bb7cf6756ea9adc25770aede4b3ca8142949d6ef5ca0add29af912fd4")},
			},
			State{
				Keys: []Key{{Kind: Key25519, Public: []byte{1, 2, 3, 4}}},
			},
			State{
				Keys:        []Key{{Kind: Key25519, Public: []byte{5, 6, 7, 8}}},
				LastAUMHash: hashFromHex("218165fe5f757304b9deaff4ac742890364f5f509e533c74e80e0ce35e44ee1d"),
			},
		},
		{
			"Disablement",
			[]AUM{{MessageKind: AUMDisableNL, DisablementSecret: []byte{1, 2, 3, 4}, PrevAUMHash: fromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03")}},
			State{
				DisablementSecrets: [][]byte{disablementKDF([]byte{1, 2, 3, 4})},
				LastAUMHash:        hashFromHex("53898e4311d0b6087fcbb871563868a16c629d9267df851fcfa7b52b31d2bd03"),
			},
			State{},
		},
		{
			"Checkpoint",
			[]AUM{
				{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: []byte{5, 6, 7, 8}}},
				{MessageKind: AUMCheckpoint, State: &State{
					Keys: []Key{{Kind: Key25519, Public: []byte{1, 2, 3, 4}}},
				}, PrevAUMHash: fromHex("f09bda3bb7cf6756ea9adc25770aede4b3ca8142949d6ef5ca0add29af912fd4")},
			},
			State{DisablementSecrets: [][]byte{[]byte{1, 2, 3, 4}}},
			State{
				Keys:        []Key{{Kind: Key25519, Public: []byte{1, 2, 3, 4}}},
				LastAUMHash: hashFromHex("2e34f7e21883c35c8e34ec06e735f7ed8a14c3ceeb11ccb18fcbc11d51c8dabb"),
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
				if tc.Updates[i].MessageKind != AUMDisableNL {
					if got, want := *state.LastAUMHash, updateHash[:]; !bytes.Equal(got[:], want) {
						t.Errorf("expected state.LastAUMHash = %x (update %d), got %x", want, i, got)
					}
				}
			}

			if diff := cmp.Diff(tc.End, state, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("output state differs (+got, -want):\n%s", diff)
			}
		})
	}
}

func TestApplyUpdateErrors(t *testing.T) {
	tcs := []struct {
		Name    string
		Updates []AUM
		Start   State
		Error   error
	}{
		{
			"AddKey exists",
			[]AUM{{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: []byte{1, 2, 3, 4}}}},
			State{Keys: []Key{{Kind: Key25519, Public: []byte{1, 2, 3, 4}}}},
			errors.New("key already exists"),
		},
		{
			"RemoveKey notfound",
			[]AUM{{MessageKind: AUMRemoveKey, Key: &Key{Kind: Key25519, Public: []byte{1, 2, 3, 4}}}},
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
			"Bad lastAUMHash",
			[]AUM{
				{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519, Public: []byte{5, 6, 7, 8}}},
				{MessageKind: AUMRemoveKey, KeyID: []byte{1, 2, 3, 4}, PrevAUMHash: fromHex("1234")},
			},
			State{
				Keys: []Key{{Kind: Key25519, Public: []byte{1, 2, 3, 4}}},
			},
			errors.New("parent AUMHash mismatch"),
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
