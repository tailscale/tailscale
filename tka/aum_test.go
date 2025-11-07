// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"bytes"
	"encoding/base64"
	"fmt"
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
				0x04, // |- major type 0 (int), value 4 (first value, AUMUpdateKey)
				0x02, // |- major type 0 (int), value 2 (second key, PrevAUMHash)
				0xf6, // |- major type 7 (val), value null (second value, nil)
				0x04, // |- major type 0 (int), value 4 (third key, KeyID)
				0x42, // |- major type 2 (byte string), 2 items
				0x01, //    |- major type 0 (int), value 1 (byte 1)
				0x02, //    |- major type 0 (int), value 2 (byte 2)
				0x06, // |- major type 0 (int), value 6 (fourth key, Votes)
				0x02, // |- major type 0 (int), value 2 (forth value, 2)
				0x07, // |- major type 0 (int), value 7 (fifth key, Meta)
				0xa1, // |- major type 5 (map), 1 item (map[string]string type)
				0x61, //    |- major type 3 (text string), value 1 (first key, one byte long)
				0x61, //       |- byte 'a'
				0x61, //    |- major type 3 (text string), value 1 (first value, one byte long)
				0x62, //       |- byte 'b'
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
					0x05,       // |- major type 0 (int), value 5 (first value, AUMCheckpoint)
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

func fromBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("base64 decode failed: %v", err))
	}
	return data
}

// This test verifies that we can read AUMs which were serialized with
// older versions of our code.
func TestDeserializeExistingAUMs(t *testing.T) {
	for _, tt := range []struct {
		Name string
		Data []byte
		Want AUM
	}{
		{
			// This is an AUM which was created in a test tailnet, and encoded
			// on 2025-11-07 with commit d4c5b27.
			Name: "genesis-aum-2025-11-07",
			Data: fromBase64("pAEFAvYFpQH2AopYII0sLaLSEZU3W5DT1dG2WYnzjCBr4tXtVbCT2LvA9LS6WCAQhwVGDiUGRiu3P63gucZ/8otjt2DXyk+OBjbh5iWx1Fgg5VU4oRQiMoq5qK00McfpwtmjcheVammLCRwzdp2Zje9YIHDoOXe4ogPSy7lfA/veyPCKM6iZe3PTgzhQZ4W5Sh7wWCBYQtiQ6NcRlyVARJxgAj1BbbvdJQ0t4m+vHqU1J02oDlgg2sksJA+COfsBkrohwHBWlbKrpS8Mvigpl+enuHw9rIJYIB/+CUBBBLUz0KeHu7NKrg5ZEhjjPUWhNcf9QTNHjuNWWCCJuxqPZ6/IASPTmAERaoKnBNH/D+zY4p4TUGHR4fACjFggMtDAipPutgcxKnU9Tg2663gP3KlTQfztV3hBwiePZdRYIGYeD2erBkRouSL20lOnWHHlRq5kmNfN6xFb2CTaPjnXA4KjAQECAQNYIADftG3yaitV/YMoKSBP45zgyeodClumN9ZaeQg/DmCEowEBAgEDWCBRKbmWSzOyHXbHJuYn8s7dmMPDzxmIjgBoA80cBYgItAQbEWOrxfqJzIkFG/5uNUp0s/ScF4GiAVggAN+0bfJqK1X9gygpIE/jnODJ6h0KW6Y31lp5CD8OYIQCWEAENvzblKV2qx6PED5YdGy8kWa7nxEnaeuMmS5Wkx0n7CXs0XxD5f2NIE+pSv9cOsNkfYNndQkYD7ne33hQOsQM"),
			Want: AUM{
				MessageKind: AUMCheckpoint,
				State: &State{
					DisablementSecrets: [][]byte{
						fromBase64("jSwtotIRlTdbkNPV0bZZifOMIGvi1e1VsJPYu8D0tLo="),
						fromBase64("EIcFRg4lBkYrtz+t4LnGf/KLY7dg18pPjgY24eYlsdQ="),
						fromBase64("5VU4oRQiMoq5qK00McfpwtmjcheVammLCRwzdp2Zje8="),
						fromBase64("cOg5d7iiA9LLuV8D+97I8IozqJl7c9ODOFBnhblKHvA="),
						fromBase64("WELYkOjXEZclQEScYAI9QW273SUNLeJvrx6lNSdNqA4="),
						fromBase64("2sksJA+COfsBkrohwHBWlbKrpS8Mvigpl+enuHw9rII="),
						fromBase64("H/4JQEEEtTPQp4e7s0quDlkSGOM9RaE1x/1BM0eO41Y="),
						fromBase64("ibsaj2evyAEj05gBEWqCpwTR/w/s2OKeE1Bh0eHwAow="),
						fromBase64("MtDAipPutgcxKnU9Tg2663gP3KlTQfztV3hBwiePZdQ="),
						fromBase64("Zh4PZ6sGRGi5IvbSU6dYceVGrmSY183rEVvYJNo+Odc="),
					},
					Keys: []Key{
						{
							Kind:   Key25519,
							Votes:  1,
							Public: fromBase64("AN+0bfJqK1X9gygpIE/jnODJ6h0KW6Y31lp5CD8OYIQ="),
						},
						{
							Kind:   Key25519,
							Votes:  1,
							Public: fromBase64("USm5lkszsh12xybmJ/LO3ZjDw88ZiI4AaAPNHAWICLQ="),
						},
					},
					StateID1: 1253033988139371657,
					StateID2: 18333649726973670556,
				},
				Signatures: []tkatype.Signature{
					{
						KeyID:     fromBase64("AN+0bfJqK1X9gygpIE/jnODJ6h0KW6Y31lp5CD8OYIQ="),
						Signature: fromBase64("BDb825SldqsejxA+WHRsvJFmu58RJ2nrjJkuVpMdJ+wl7NF8Q+X9jSBPqUr/XDrDZH2DZ3UJGA+53t94UDrEDA=="),
					},
				},
			},
		},
	} {
		t.Run(tt.Name, func(t *testing.T) {
			var got AUM

			if err := got.Unserialize(tt.Data); err != nil {
				t.Fatalf("Unserialize: %v", err)
			}

			if diff := cmp.Diff(got, tt.Want); diff != "" {
				t.Fatalf("wrong AUM (-got, +want):\n%s", diff)
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
				Signatures: []tkatype.Signature{{KeyID: key.MustID()}},
			},
			State{
				Keys: []Key{key},
			},
			2,
		},
		{
			"Multiple keys",
			AUM{
				Signatures: []tkatype.Signature{{KeyID: key.MustID()}, {KeyID: key2.MustID()}},
			},
			State{
				Keys: []Key{key, key2},
			},
			4,
		},
		{
			"Double use",
			AUM{
				Signatures: []tkatype.Signature{{KeyID: key.MustID()}, {KeyID: key.MustID()}},
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
