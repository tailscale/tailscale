// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"crypto/ed25519"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/key"
)

func TestSigDirect(t *testing.T) {
	node := key.NewNode()
	nodeKeyPub, _ := node.Public().MarshalBinary()

	// Verification key (the key used to sign)
	pub, priv := testingKey25519(t, 1)
	k := Key{Kind: Key25519, Public: pub, Votes: 2}

	sig := NodeKeySignature{
		SigKind: SigDirect,
		KeyID:   k.ID(),
		Pubkey:  nodeKeyPub,
	}
	sigHash := sig.SigHash()
	sig.Signature = ed25519.Sign(priv, sigHash[:])

	if sig.SigHash() != sigHash {
		t.Errorf("sigHash changed after signing: %x != %x", sig.SigHash(), sigHash)
	}

	if err := sig.verifySignature(node.Public(), k); err != nil {
		t.Fatalf("verifySignature() failed: %v", err)
	}

	// Test verification fails when verifying for a different node
	if err := sig.verifySignature(key.NewNode().Public(), k); err == nil {
		t.Error("verifySignature() did not error for different nodekey")
	}

	// Test verification fails if the wrong verification key is provided
	copy(k.Public, []byte{1, 2, 3, 4})
	if err := sig.verifySignature(node.Public(), k); err == nil {
		t.Error("verifySignature() did not error for wrong verification key")
	}
}

func TestSigNested(t *testing.T) {
	// Network-lock key (the key used to sign the nested sig)
	pub, priv := testingKey25519(t, 1)
	k := Key{Kind: Key25519, Public: pub, Votes: 2}
	// Rotation key (the key used to sign the outer sig)
	rPub, rPriv := testingKey25519(t, 2)
	// The old node key which is being rotated out
	oldNode := key.NewNode()
	oldPub, _ := oldNode.Public().MarshalBinary()
	// The new node key that is being rotated in
	node := key.NewNode()
	nodeKeyPub, _ := node.Public().MarshalBinary()

	// The original signature for the old node key, signed by
	// the network-lock key.
	nestedSig := NodeKeySignature{
		SigKind:        SigDirect,
		KeyID:          k.ID(),
		Pubkey:         oldPub,
		WrappingPubkey: rPub,
	}
	sigHash := nestedSig.SigHash()
	nestedSig.Signature = ed25519.Sign(priv, sigHash[:])
	if err := nestedSig.verifySignature(oldNode.Public(), k); err != nil {
		t.Fatalf("verifySignature(oldNode) failed: %v", err)
	}

	// The signature authorizing the rotation, signed by the
	// rotation key & embedding the original signature.
	sig := NodeKeySignature{
		SigKind: SigRotation,
		KeyID:   k.ID(),
		Pubkey:  nodeKeyPub,
		Nested:  &nestedSig,
	}
	sigHash = sig.SigHash()
	sig.Signature = ed25519.Sign(rPriv, sigHash[:])

	if err := sig.verifySignature(node.Public(), k); err != nil {
		t.Fatalf("verifySignature(node) failed: %v", err)
	}

	// Test verification fails if the wrong verification key is provided
	kBad := Key{Kind: Key25519, Public: []byte{1, 2, 3, 4}, Votes: 2}
	if err := sig.verifySignature(node.Public(), kBad); err == nil {
		t.Error("verifySignature() did not error for wrong verification key")
	}

	// Test verification fails if the inner signature is invalid
	tmp := make([]byte, ed25519.SignatureSize)
	copy(tmp, nestedSig.Signature)
	copy(nestedSig.Signature, []byte{1, 2, 3, 4})
	if err := sig.verifySignature(node.Public(), k); err == nil {
		t.Error("verifySignature(node) succeeded with bad inner signature")
	}
	copy(nestedSig.Signature, tmp)

	// Test verification fails if the outer signature is invalid
	copy(sig.Signature, []byte{1, 2, 3, 4})
	if err := sig.verifySignature(node.Public(), k); err == nil {
		t.Error("verifySignature(node) succeeded with bad outer signature")
	}

	// Test verification fails if the outer signature is signed with a
	// different public key to whats specified in WrappingPubkey
	sig.Signature = ed25519.Sign(priv, sigHash[:])
	if err := sig.verifySignature(node.Public(), k); err == nil {
		t.Error("verifySignature(node) succeeded with different signature")
	}
}

func TestSigNested_DeepNesting(t *testing.T) {
	// Network-lock key (the key used to sign the nested sig)
	pub, priv := testingKey25519(t, 1)
	k := Key{Kind: Key25519, Public: pub, Votes: 2}
	// Rotation key (the key used to sign the outer sig)
	rPub, rPriv := testingKey25519(t, 2)
	// The old node key which is being rotated out
	oldNode := key.NewNode()
	oldPub, _ := oldNode.Public().MarshalBinary()

	// The original signature for the old node key, signed by
	// the network-lock key.
	nestedSig := NodeKeySignature{
		SigKind:        SigDirect,
		KeyID:          k.ID(),
		Pubkey:         oldPub,
		WrappingPubkey: rPub,
	}
	sigHash := nestedSig.SigHash()
	nestedSig.Signature = ed25519.Sign(priv, sigHash[:])
	if err := nestedSig.verifySignature(oldNode.Public(), k); err != nil {
		t.Fatalf("verifySignature(oldNode) failed: %v", err)
	}

	outer := nestedSig
	var lastNodeKey key.NodePrivate
	for i := 0; i < 100; i++ {
		lastNodeKey = key.NewNode()
		nodeKeyPub, _ := lastNodeKey.Public().MarshalBinary()

		tmp := outer
		sig := NodeKeySignature{
			SigKind: SigRotation,
			KeyID:   k.ID(),
			Pubkey:  nodeKeyPub,
			Nested:  &tmp,
		}
		sigHash = sig.SigHash()
		sig.Signature = ed25519.Sign(rPriv, sigHash[:])

		outer = sig
	}

	if err := outer.verifySignature(lastNodeKey.Public(), k); err != nil {
		t.Fatalf("verifySignature(lastNodeKey) failed: %v", err)
	}

	// Test verification fails if the inner signature is invalid
	tmp := make([]byte, ed25519.SignatureSize)
	copy(tmp, nestedSig.Signature)
	copy(nestedSig.Signature, []byte{1, 2, 3, 4})
	if err := outer.verifySignature(lastNodeKey.Public(), k); err == nil {
		t.Error("verifySignature(lastNodeKey) succeeded with bad inner signature")
	}
	copy(nestedSig.Signature, tmp)

	// Test verification fails if an intermediate signature is invalid
	copy(outer.Nested.Nested.Signature, []byte{1, 2, 3, 4})
	if err := outer.verifySignature(lastNodeKey.Public(), k); err == nil {
		t.Error("verifySignature(lastNodeKey) succeeded with bad outer signature")
	}
}

func TestSigCredential(t *testing.T) {
	// Network-lock key (the key used to sign the nested sig)
	pub, priv := testingKey25519(t, 1)
	k := Key{Kind: Key25519, Public: pub, Votes: 2}
	// 'credential' key (the one being delegated to)
	cPub, cPriv := testingKey25519(t, 2)
	// The node key being certified
	node := key.NewNode()
	nodeKeyPub, _ := node.Public().MarshalBinary()

	// The signature certifying delegated trust to another
	// public key.
	nestedSig := NodeKeySignature{
		SigKind:        SigCredential,
		KeyID:          k.ID(),
		WrappingPubkey: cPub,
	}
	sigHash := nestedSig.SigHash()
	nestedSig.Signature = ed25519.Sign(priv, sigHash[:])

	// The signature authorizing the node key, signed by the
	// delegated key & embedding the original signature.
	sig := NodeKeySignature{
		SigKind: SigRotation,
		KeyID:   k.ID(),
		Pubkey:  nodeKeyPub,
		Nested:  &nestedSig,
	}
	sigHash = sig.SigHash()
	sig.Signature = ed25519.Sign(cPriv, sigHash[:])
	if err := sig.verifySignature(node.Public(), k); err != nil {
		t.Fatalf("verifySignature(node) failed: %v", err)
	}

	// Test verification fails if the wrong verification key is provided
	kBad := Key{Kind: Key25519, Public: []byte{1, 2, 3, 4}, Votes: 2}
	if err := sig.verifySignature(node.Public(), kBad); err == nil {
		t.Error("verifySignature() did not error for wrong verification key")
	}

	// Test someone can't misuse our public API for verifying node-keys
	a, _ := Open(newTestchain(t, "G1\nG1.template = genesis",
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{k},
			DisablementSecrets: [][]byte{disablementKDF([]byte{1, 2, 3})},
		}})).Chonk())
	if err := a.NodeKeyAuthorized(node.Public(), nestedSig.Serialize()); err == nil {
		t.Error("NodeKeyAuthorized(SigCredential, node) did not fail")
	}
	// but that they can use it properly (nested in a SigRotation)
	if err := a.NodeKeyAuthorized(node.Public(), sig.Serialize()); err != nil {
		t.Errorf("NodeKeyAuthorized(SigRotation{SigCredential}, node) failed: %v", err)
	}

	// Test verification fails if the inner signature is invalid
	tmp := make([]byte, ed25519.SignatureSize)
	copy(tmp, nestedSig.Signature)
	copy(nestedSig.Signature, []byte{1, 2, 3, 4})
	if err := sig.verifySignature(node.Public(), k); err == nil {
		t.Error("verifySignature(node) succeeded with bad inner signature")
	}
	copy(nestedSig.Signature, tmp)

	// Test verification fails if the outer signature is invalid
	copy(tmp, sig.Signature)
	copy(sig.Signature, []byte{1, 2, 3, 4})
	if err := sig.verifySignature(node.Public(), k); err == nil {
		t.Error("verifySignature(node) succeeded with bad outer signature")
	}
	copy(sig.Signature, tmp)

	// Test verification fails if we attempt to check a different node-key
	otherNode := key.NewNode()
	if err := sig.verifySignature(otherNode.Public(), k); err == nil {
		t.Error("verifySignature(otherNode) succeeded with different principal")
	}

	// Test verification fails if the outer signature is signed with a
	// different public key to whats specified in WrappingPubkey
	sig.Signature = ed25519.Sign(priv, sigHash[:])
	if err := sig.verifySignature(node.Public(), k); err == nil {
		t.Error("verifySignature(node) succeeded with different signature")
	}
}

func TestSigSerializeUnserialize(t *testing.T) {
	nodeKeyPub := []byte{1, 2, 3, 4}
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}
	sig := NodeKeySignature{
		SigKind: SigDirect,
		KeyID:   key.ID(),
		Pubkey:  nodeKeyPub,
		Nested: &NodeKeySignature{
			SigKind: SigDirect,
			KeyID:   key.ID(),
			Pubkey:  nodeKeyPub,
		},
	}
	sigHash := sig.SigHash()
	sig.Signature = ed25519.Sign(priv, sigHash[:])

	var decoded NodeKeySignature
	if err := decoded.Unserialize(sig.Serialize()); err != nil {
		t.Fatalf("Unserialize() failed: %v", err)
	}
	if diff := cmp.Diff(sig, decoded); diff != "" {
		t.Errorf("unmarshalled version differs (-want, +got):\n%s", diff)
	}
}
