// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"tailscale.com/types/tkatype"
)

// fuzzNKS builds a rotation chain of the given depth, with a direct signature
// at the leaf. Nested signatures drive the authorizingKeyID recursion.
func fuzzNKS(depth int) *NodeKeySignature {
	sig := &NodeKeySignature{
		SigKind: SigDirect,
		KeyID:   make([]byte, 32),
		Pubkey:  make([]byte, 32),
	}
	for range depth {
		sig = &NodeKeySignature{
			SigKind: SigRotation,
			Nested:  sig,
			Pubkey:  make([]byte, 32),
		}
	}
	return sig
}

// fuzzKey generates a valid signing key for seeds.
func fuzzKey(f *testing.F, votes uint) Key {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	return Key{
		Kind:   Key25519,
		Votes:  votes,
		Public: priv.Public().(ed25519.PublicKey),
		Meta:   map[string]string{"name": "fuzz"},
	}
}

// fuzzDisablementSecrets returns n distinct valid disablement secrets.
func fuzzDisablementSecrets(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		ds := make([]byte, disablementLength)
		for j := range ds {
			ds[j] = byte(i)
		}
		out[i] = ds
	}
	return out
}

// FuzzAUMUnserializeValidate feeds arbitrary bytes through the CBOR
// decode-then-static-validate pipeline for an AUM. Neither step may panic.
func FuzzAUMUnserializeValidate(f *testing.F) {
	k := fuzzKey(f, 1)

	// Each AUM kind, valid
	f.Add([]byte((&AUM{MessageKind: AUMNoOp}).Serialize()))
	f.Add([]byte((&AUM{
		MessageKind: AUMAddKey,
		PrevAUMHash: []byte{1, 2, 3},
		Key:         &k,
	}).Serialize()))
	f.Add([]byte((&AUM{MessageKind: AUMRemoveKey, KeyID: make([]byte, 32)}).Serialize()))
	votes := uint(1)
	f.Add([]byte((&AUM{MessageKind: AUMUpdateKey, KeyID: make([]byte, 32), Votes: &votes}).Serialize()))
	f.Add([]byte((&AUM{
		MessageKind: AUMUpdateKey,
		KeyID:       make([]byte, 32),
		Meta:        map[string]string{"name": "new"},
	}).Serialize()))
	// Checkpoint with a valid State, so staticValidateCheckpoint is reached
	f.Add([]byte((&AUM{
		MessageKind: AUMCheckpoint,
		State: &State{
			DisablementValues: fuzzDisablementSecrets(1),
			Keys:              []Key{k},
		},
	}).Serialize()))
	// Multiple disablement values and multiple keys
	f.Add([]byte((&AUM{
		MessageKind: AUMCheckpoint,
		State: &State{
			DisablementValues: fuzzDisablementSecrets(2),
			Keys:              []Key{k, fuzzKey(f, 2)},
		},
	}).Serialize()))
	// Signed AUMs, so the Signatures loop is seeded
	signedNoOp := &AUM{MessageKind: AUMNoOp}
	signedNoOp.Signatures = []tkatype.Signature{{
		KeyID:     make([]byte, 32),
		Signature: make([]byte, ed25519.SignatureSize),
	}}
	f.Add([]byte(signedNoOp.Serialize()))
	twoSig := &AUM{MessageKind: AUMAddKey, Key: &k, PrevAUMHash: []byte{9, 9}}
	twoSig.Signatures = []tkatype.Signature{{
		KeyID:     make([]byte, 32),
		Signature: make([]byte, ed25519.SignatureSize),
	}, {
		KeyID:     make([]byte, 31), // malformed: wrong KeyID length
		Signature: make([]byte, ed25519.SignatureSize),
	}}
	f.Add([]byte(twoSig.Serialize()))
	// Invalid/edge kinds and shapes
	f.Add([]byte((&AUM{MessageKind: AUMInvalid}).Serialize()))
	f.Add([]byte((&AUM{MessageKind: AUMKind(200)}).Serialize()))
	// Empty-but-non-nil PrevAUMHash; rejected by StaticValidate
	f.Add([]byte((&AUM{MessageKind: AUMNoOp, PrevAUMHash: []byte{}}).Serialize()))
	// Zero-vote and over-vote keys
	zeroVotes := k
	zeroVotes.Votes = 0
	f.Add([]byte((&AUM{MessageKind: AUMAddKey, Key: &zeroVotes}).Serialize()))
	bigVotes := k
	bigVotes.Votes = 4097
	f.Add([]byte((&AUM{MessageKind: AUMAddKey, Key: &bigVotes}).Serialize()))
	// Empty disablement value; fails the length check
	f.Add([]byte((&AUM{
		MessageKind: AUMCheckpoint,
		State: &State{
			DisablementValues: [][]byte{make([]byte, disablementLength-1)},
			Keys:              []Key{k},
		},
	}).Serialize()))

	f.Fuzz(func(t *testing.T, data []byte) {
		var a AUM
		if err := a.Unserialize(data); err != nil {
			return
		}
		_ = a.StaticValidate()
	})
}

// FuzzNodeKeySignatureUnserialize feeds arbitrary bytes through the CBOR decode of
// a NodeKeySignature, then authorizingKeyID. It must not panic on malformed input,
// including deeply nested rotation chains that drive authorizingKeyID's recursion.
func FuzzNodeKeySignatureUnserialize(f *testing.F) {
	// Direct and credential signatures, with KeyIDs
	f.Add([]byte((&NodeKeySignature{SigKind: SigDirect}).Serialize()))
	f.Add([]byte((&NodeKeySignature{
		SigKind: SigDirect,
		KeyID:   make([]byte, 32),
		Pubkey:  make([]byte, 32),
	}).Serialize()))
	f.Add([]byte((&NodeKeySignature{
		SigKind:        SigCredential,
		KeyID:          make([]byte, 32),
		WrappingPubkey: make([]byte, 32),
	}).Serialize()))
	// Invalid and unknown signature kinds; hit the default error path
	f.Add([]byte((&NodeKeySignature{SigKind: SigInvalid}).Serialize()))
	f.Add([]byte((&NodeKeySignature{SigKind: SigKind(200)}).Serialize()))
	// Rotation without a nested signature; takes the error path
	f.Add([]byte((&NodeKeySignature{SigKind: SigRotation, Pubkey: make([]byte, 32)}).Serialize()))
	// Nested rotation over a credential, as generated for wrapped auth keys
	nested := &NodeKeySignature{
		SigKind: SigRotation,
		Nested: &NodeKeySignature{
			SigKind:        SigCredential,
			KeyID:          make([]byte, 32),
			WrappingPubkey: make([]byte, 33),
		},
		Pubkey: make([]byte, 32),
	}
	f.Add([]byte(nested.Serialize()))
	// Chains up to and past the CBOR nesting limit, targeting authorizingKeyID's recursion
	f.Add([]byte(fuzzNKS(1).Serialize()))
	f.Add([]byte(fuzzNKS(3).Serialize()))
	f.Add([]byte(fuzzNKS(14).Serialize()))
	f.Add([]byte(fuzzNKS(15).Serialize())) // max-depth decodable chain
	f.Add([]byte(fuzzNKS(16).Serialize())) // exceeds the limit; decode fails

	f.Fuzz(func(t *testing.T, data []byte) {
		var s NodeKeySignature
		if err := s.Unserialize(data); err != nil {
			return
		}
		_, _ = s.authorizingKeyID()
	})
}
