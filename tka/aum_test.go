// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/blake2s"
	"tailscale.com/types/tkatype"
)

func TestSerialization(t *testing.T) {
	uint2 := uint(2)
	var fakeAUMHash AUMHash

	tcs := []struct {
		Name   string
		AUM    AUM
		Expect []byte
	}{
		{
			"AddKey",
			AUM{MessageKind: AUMAddKey, Key: &Key{}},
			[]byte{
				0xa3, // major type 5 (map), 3 items
				0x01, // |- major type 0 (int), value 1 (first key, MessageKind)
				0x01, // |- major type 0 (int), value 1 (first value, AUMAddKey)
				0x02, // |- major type 0 (int), value 2 (second key, PrevAUMHash)
				0xf6, // |- major type 7 (val), value null (second value, nil)
				0x03, // |- major type 0 (int), value 3 (third key, Key)
				0xa3, // |- major type 5 (map), 3 items (type Key)
				0x01, //    |- major type 0 (int), value 1 (first key, Kind)
				0x00, //    |- major type 0 (int), value 0 (first value)
				0x02, //    |- major type 0 (int), value 2 (second key, Votes)
				0x00, //    |- major type 0 (int), value 0 (first value)
				0x03, //    |- major type 0 (int), value 3 (third key, Public)
				0xf6, //    |- major type 7 (val), value null (third value, nil)
			},
		},
		{
			"RemoveKey",
			AUM{MessageKind: AUMRemoveKey, KeyID: []byte{1, 2}},
			[]byte{
				0xa3, // major type 5 (map), 3 items
				0x01, // |- major type 0 (int), value 1 (first key, MessageKind)
				0x02, // |- major type 0 (int), value 2 (first value, AUMRemoveKey)
				0x02, // |- major type 0 (int), value 2 (second key, PrevAUMHash)
				0xf6, // |- major type 7 (val), value null (second value, nil)
				0x04, // |- major type 0 (int), value 4 (third key, KeyID)
				0x42, // |- major type 2 (byte string), 2 items
				0x01, //    |- major type 0 (int), value 1 (byte 1)
				0x02, //    |- major type 0 (int), value 2 (byte 2)
			},
		},
		{
			"UpdateKey",
			AUM{MessageKind: AUMUpdateKey, Votes: &uint2, KeyID: []byte{1, 2}, Meta: map[string]string{"a": "b"}},
			[]byte{
				0xa5, // major type 5 (map), 5 items
				0x01, // |- major type 0 (int), value 1 (first key, MessageKind)
				0x05, // |- major type 0 (int), value 2 (first value, AUMUpdateKey)
				0x02, // |- major type 0 (int), value 2 (second key, PrevAUMHash)
				0xf6, // |- major type 7 (val), value null (second value, nil)
				0x04, // |- major type 0 (int), value 4 (third key, KeyID)
				0x42, // |- major type 2 (byte string), 2 items
				0x01, //    |- major type 0 (int), value 1 (byte 1)
				0x02, //    |- major type 0 (int), value 2 (byte 2)
				0x07, // |- major type 0 (int), value 7 (fourth key, Votes)
				0x02, // |- major type 0 (int), value 2 (forth value, 2)
				0x08, // |- major type 0 (int), value 8 (fifth key, Meta)
				0xa1, // |- major type 5 (map), 1 item (map[string]string type)
				0x61, //    |- major type 3 (text string), value 1 (first key, one byte long)
				0x61, //       |- byte 'a'
				0x61, //    |- major type 3 (text string), value 1 (first value, one byte long)
				0x62, //       |- byte 'b'
			},
		},
		{
			"DisableNL",
			AUM{MessageKind: AUMDisableNL, PrevAUMHash: []byte{1, 2}, DisablementSecret: []byte{3, 4}},
			[]byte{
				0xa3, // major type 5 (map), 3 items
				0x01, // |- major type 0 (int), value 1 (first key, MessageKind)
				0x03, // |- major type 0 (int), value 3 (first value, AUMDisableNL)
				0x02, // |- major type 0 (int), value 2 (second key, PrevAUMHash)
				0x42, // |- major type 2 (byte string), 2 items (second value)
				0x01, //    |- major type 0 (int), value 1 (byte 1)
				0x02, //    |- major type 0 (int), value 2 (byte 2)
				0x06, // |- major type 0 (int), value 6 (third key, DisablementSecret)
				0x42, // |- major type 2 (byte string), 2 items (third value)
				0x03, //    |- major type 0 (int), value 3 (byte 3)
				0x04, //    |- major type 0 (int), value 4 (byte 4)
			},
		},
		{
			"Checkpoint",
			AUM{MessageKind: AUMCheckpoint, PrevAUMHash: []byte{1, 2}, State: &State{
				LastAUMHash: &fakeAUMHash,
				Keys: []Key{
					{Kind: Key25519, Public: []byte{5, 6}},
				},
			}},
			append(
				append([]byte{
					0xa3,       // major type 5 (map), 3 items
					0x01,       // |- major type 0 (int), value 1 (first key, MessageKind)
					0x06,       // |- major type 0 (int), value 6 (first value, AUMCheckpoint)
					0x02,       // |- major type 0 (int), value 2 (second key, PrevAUMHash)
					0x42,       // |- major type 2 (byte string), 2 items (second value)
					0x01,       //    |- major type 0 (int), value 1 (byte 1)
					0x02,       //    |- major type 0 (int), value 2 (byte 2)
					0x05,       // |- major type 0 (int), value 5 (third key, State)
					0xa3,       // |- major type 5 (map), 3 items (third value, State type)
					0x01,       //   |- major type 0 (int), value 1 (first key, LastAUMHash)
					0x58, 0x20, //   |- major type 2 (byte string), 32 items (first value)
				},
					bytes.Repeat([]byte{0}, 32)...),
				[]byte{
					0x02, //     |- major type 0 (int), value 2 (second key, DisablementSecrets)
					0xf6, //     |- major type 7 (val), value null (second value, nil)
					0x03, //     |- major type 0 (int), value 3 (third key, Keys)
					0x81, //     |- major type 4 (array), value 1 (one item in array)
					0xa3, //       |- major type 5 (map), 3 items (Key type)
					0x01, //          |- major type 0 (int), value 1 (first key, Kind)
					0x01, //          |- major type 0 (int), value 1 (first value, Key25519)
					0x02, //          |- major type 0 (int), value 2 (second key, Votes)
					0x00, //          |- major type 0 (int), value 0 (second value, 0)
					0x03, //          |- major type 0 (int), value 3 (third key, Public)
					0x42, //          |- major type 2 (byte string), 2 items (third value)
					0x05, //             |- major type 0 (int), value 5 (byte 5)
					0x06, //             |- major type 0 (int), value 6 (byte 6)
				}...),
		},
		{
			"Signature",
			AUM{MessageKind: AUMAddKey, Signatures: []tkatype.Signature{{KeyID: []byte{1}}}},
			[]byte{
				0xa3, // major type 5 (map), 3 items
				0x01, // |- major type 0 (int), value 1 (first key, MessageKind)
				0x01, // |- major type 0 (int), value 1 (first value, AUMAddKey)
				0x02, // |- major type 0 (int), value 2 (second key, PrevAUMHash)
				0xf6, // |- major type 7 (val), value null (second value, nil)
				0x17, // |- major type 0 (int), value 22 (third key, Signatures)
				0x81, // |- major type 4 (array), value 1 (one item in array)
				0xa2, //   |- major type 5 (map), 2 items (Signature type)
				0x01, //     |- major type 0 (int), value 1 (first key, KeyID)
				0x41, //     |- major type 2 (byte string), 1 item
				0x01, //       |- major type 0 (int), value 1 (byte 1)
				0x02, //     |- major type 0 (int), value 2 (second key, Signature)
				0xf6, //     |- major type 7 (val), value null (second value, nil)
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			data := []byte(tc.AUM.Serialize())
			if diff := cmp.Diff(tc.Expect, data); diff != "" {
				t.Errorf("serialization differs (-want, +got):\n%s", diff)
			}

			var decodedAUM AUM
			if err := decodedAUM.Unserialize(data); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}
			if diff := cmp.Diff(tc.AUM, decodedAUM); diff != "" {
				t.Errorf("unmarshalled version differs (-want, +got):\n%s", diff)
			}
		})
	}
}

func TestAUMWeight(t *testing.T) {
	var fakeKeyID [blake2s.Size]byte
	testingRand(t, 1).Read(fakeKeyID[:])

	pub, _ := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}
	pub, _ = testingKey25519(t, 2)
	key2 := Key{Kind: Key25519, Public: pub, Votes: 2}

	tcs := []struct {
		Name  string
		AUM   AUM
		State State
		Want  uint
	}{
		{
			"Empty",
			AUM{},
			State{},
			0,
		},
		{
			"Key unknown",
			AUM{
				Signatures: []tkatype.Signature{{KeyID: fakeKeyID[:]}},
			},
			State{},
			0,
		},
		{
			"Unary key",
			AUM{
				Signatures: []tkatype.Signature{{KeyID: key.ID()}},
			},
			State{
				Keys: []Key{key},
			},
			2,
		},
		{
			"Multiple keys",
			AUM{
				Signatures: []tkatype.Signature{{KeyID: key.ID()}, {KeyID: key2.ID()}},
			},
			State{
				Keys: []Key{key, key2},
			},
			4,
		},
		{
			"Double use",
			AUM{
				Signatures: []tkatype.Signature{{KeyID: key.ID()}, {KeyID: key.ID()}},
			},
			State{
				Keys: []Key{key},
			},
			2,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.Name, func(t *testing.T) {
			got := tc.AUM.Weight(tc.State)
			if got != tc.Want {
				t.Errorf("Weight() = %d, want %d", got, tc.Want)
			}
		})
	}
}

func TestAUMHashes(t *testing.T) {
	// .Hash(): a hash over everything.
	// .SigHash(): a hash over everything except the signatures.
	//             The signatures are over a hash of the AUM, so
	//             using SigHash() breaks this circularity.

	aum := AUM{MessageKind: AUMAddKey, Key: &Key{Kind: Key25519}}
	sigHash1 := aum.SigHash()
	aumHash1 := aum.Hash()

	aum.Signatures = []tkatype.Signature{{KeyID: []byte{1, 2, 3, 4}}}
	sigHash2 := aum.SigHash()
	aumHash2 := aum.Hash()
	if len(aum.Signatures) != 1 {
		t.Error("signature was removed by one of the hash functions")
	}

	if !bytes.Equal(sigHash1[:], sigHash1[:]) {
		t.Errorf("signature hash dependent on signatures!\n\t1 = %x\n\t2 = %x", sigHash1, sigHash2)
	}
	if bytes.Equal(aumHash1[:], aumHash2[:]) {
		t.Error("aum hash didnt change")
	}
}
