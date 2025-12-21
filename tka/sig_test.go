// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tka

import (
	"crypto/ed25519"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

func TestSigDirect(t *testing.T) {
	node := key.NewNode()
	nodeKeyPub, _ := node.Public().MarshalBinary()

	// Verification key (the key used to sign)
	pub, priv := testingKey25519(t, 1)
	k := Key{Kind: Key25519, Public: pub, Votes: 2}

	sig := NodeKeySignature{
		SigKind: SigDirect,
		KeyID:   k.MustID(),
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
		KeyID:          k.MustID(),
		Pubkey:         oldPub,
		WrappingPubkey: rPub,
	}
	sigHash := nestedSig.SigHash()
	nestedSig.Signature = ed25519.Sign(priv, sigHash[:])
	if err := nestedSig.verifySignature(oldNode.Public(), k); err != nil {
		t.Fatalf("verifySignature(oldNode) failed: %v", err)
	}
	if ln := sigChainLength(nestedSig); ln != 1 {
		t.Errorf("nestedSig chain length = %v, want 1", ln)
	}

	// The signature authorizing the rotation, signed by the
	// rotation key & embedding the original signature.
	sig := NodeKeySignature{
		SigKind: SigRotation,
		Pubkey:  nodeKeyPub,
		Nested:  &nestedSig,
	}
	sigHash = sig.SigHash()
	sig.Signature = ed25519.Sign(rPriv, sigHash[:])

	if err := sig.verifySignature(node.Public(), k); err != nil {
		t.Fatalf("verifySignature(node) failed: %v", err)
	}
	if ln := sigChainLength(sig); ln != 2 {
		t.Errorf("sig chain length = %v, want 2", ln)
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
	// different public key to what's specified in WrappingPubkey
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
		KeyID:          k.MustID(),
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
	for range 15 { // 15 = max nesting level for CBOR
		lastNodeKey = key.NewNode()
		nodeKeyPub, _ := lastNodeKey.Public().MarshalBinary()

		tmp := outer
		sig := NodeKeySignature{
			SigKind: SigRotation,
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

	// Test this works with our public API
	a, _ := Open(newTestchain(t, "G1\nG1.template = genesis",
		optTemplate("genesis", AUM{MessageKind: AUMCheckpoint, State: &State{
			Keys:               []Key{k},
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
		}})).Chonk())
	if err := a.NodeKeyAuthorized(lastNodeKey.Public(), outer.Serialize()); err != nil {
		t.Errorf("NodeKeyAuthorized(lastNodeKey) failed: %v", err)
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
		KeyID:          k.MustID(),
		WrappingPubkey: cPub,
	}
	sigHash := nestedSig.SigHash()
	nestedSig.Signature = ed25519.Sign(priv, sigHash[:])

	// The signature authorizing the node key, signed by the
	// delegated key & embedding the original signature.
	sig := NodeKeySignature{
		SigKind: SigRotation,
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
			DisablementSecrets: [][]byte{DisablementKDF([]byte{1, 2, 3})},
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
	// different public key to what's specified in WrappingPubkey
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
		KeyID:   key.MustID(),
		Pubkey:  nodeKeyPub,
		Nested: &NodeKeySignature{
			SigKind: SigDirect,
			KeyID:   key.MustID(),
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

func TestNodeKeySignatureRotationDetails(t *testing.T) {
	// Trusted network lock key
	pub, priv := testingKey25519(t, 1)
	k := Key{Kind: Key25519, Public: pub, Votes: 2}

	// 'credential' key (the one being delegated to)
	cPub, cPriv := testingKey25519(t, 2)

	n1, n2, n3 := key.NewNode(), key.NewNode(), key.NewNode()
	n1pub, _ := n1.Public().MarshalBinary()
	n2pub, _ := n2.Public().MarshalBinary()
	n3pub, _ := n3.Public().MarshalBinary()

	tests := []struct {
		name    string
		nodeKey key.NodePublic
		sigFn   func() NodeKeySignature
		want    *RotationDetails
	}{
		{
			name:    "SigDirect",
			nodeKey: n1.Public(),
			sigFn: func() NodeKeySignature {
				s := NodeKeySignature{
					SigKind: SigDirect,
					KeyID:   pub,
					Pubkey:  n1pub,
				}
				sigHash := s.SigHash()
				s.Signature = ed25519.Sign(priv, sigHash[:])
				return s
			},
			want: nil,
		},
		{
			name:    "SigWrappedCredential",
			nodeKey: n1.Public(),
			sigFn: func() NodeKeySignature {
				nestedSig := NodeKeySignature{
					SigKind:        SigCredential,
					KeyID:          pub,
					WrappingPubkey: cPub,
				}
				sigHash := nestedSig.SigHash()
				nestedSig.Signature = ed25519.Sign(priv, sigHash[:])

				sig := NodeKeySignature{
					SigKind: SigRotation,
					Pubkey:  n1pub,
					Nested:  &nestedSig,
				}
				sigHash = sig.SigHash()
				sig.Signature = ed25519.Sign(cPriv, sigHash[:])
				return sig
			},
			want: &RotationDetails{
				InitialSig: &NodeKeySignature{
					SigKind:        SigCredential,
					KeyID:          pub,
					WrappingPubkey: cPub,
				},
			},
		},
		{
			name:    "SigRotation",
			nodeKey: n2.Public(),
			sigFn: func() NodeKeySignature {
				nestedSig := NodeKeySignature{
					SigKind:        SigDirect,
					Pubkey:         n1pub,
					KeyID:          pub,
					WrappingPubkey: cPub,
				}
				sigHash := nestedSig.SigHash()
				nestedSig.Signature = ed25519.Sign(priv, sigHash[:])

				sig := NodeKeySignature{
					SigKind: SigRotation,
					Pubkey:  n2pub,
					Nested:  &nestedSig,
				}
				sigHash = sig.SigHash()
				sig.Signature = ed25519.Sign(cPriv, sigHash[:])
				return sig
			},
			want: &RotationDetails{
				InitialSig: &NodeKeySignature{
					SigKind:        SigDirect,
					Pubkey:         n1pub,
					KeyID:          pub,
					WrappingPubkey: cPub,
				},
				PrevNodeKeys: []key.NodePublic{n1.Public()},
			},
		},
		{
			name:    "SigRotationNestedTwice",
			nodeKey: n3.Public(),
			sigFn: func() NodeKeySignature {
				initialSig := NodeKeySignature{
					SigKind:        SigDirect,
					Pubkey:         n1pub,
					KeyID:          pub,
					WrappingPubkey: cPub,
				}
				sigHash := initialSig.SigHash()
				initialSig.Signature = ed25519.Sign(priv, sigHash[:])

				prevRotation := NodeKeySignature{
					SigKind: SigRotation,
					Pubkey:  n2pub,
					Nested:  &initialSig,
				}
				sigHash = prevRotation.SigHash()
				prevRotation.Signature = ed25519.Sign(cPriv, sigHash[:])

				sig := NodeKeySignature{
					SigKind: SigRotation,
					Pubkey:  n3pub,
					Nested:  &prevRotation,
				}
				sigHash = sig.SigHash()
				sig.Signature = ed25519.Sign(cPriv, sigHash[:])

				return sig
			},
			want: &RotationDetails{
				InitialSig: &NodeKeySignature{
					SigKind:        SigDirect,
					Pubkey:         n1pub,
					KeyID:          pub,
					WrappingPubkey: cPub,
				},
				PrevNodeKeys: []key.NodePublic{n2.Public(), n1.Public()},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.want != nil {
				initialHash := tt.want.InitialSig.SigHash()
				tt.want.InitialSig.Signature = ed25519.Sign(priv, initialHash[:])
			}

			sig := tt.sigFn()
			if err := sig.verifySignature(tt.nodeKey, k); err != nil {
				t.Fatalf("verifySignature(node) failed: %v", err)
			}
			got, err := sig.rotationDetails()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rotationDetails() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeWrappedAuthkey(t *testing.T) {
	k, isWrapped, sig, priv := DecodeWrappedAuthkey("tskey-32mjsdkdsffds9o87dsfkjlh", nil)
	if want := "tskey-32mjsdkdsffds9o87dsfkjlh"; k != want {
		t.Errorf("decodeWrappedAuthkey(<unwrapped-key>).key = %q, want %q", k, want)
	}
	if isWrapped {
		t.Error("decodeWrappedAuthkey(<unwrapped-key>).isWrapped = true, want false")
	}
	if sig != nil {
		t.Errorf("decodeWrappedAuthkey(<unwrapped-key>).sig = %v, want nil", sig)
	}
	if priv != nil {
		t.Errorf("decodeWrappedAuthkey(<unwrapped-key>).priv = %v, want nil", priv)
	}

	k, isWrapped, sig, priv = DecodeWrappedAuthkey("tskey-auth-k7UagY1CNTRL-ZZZZZ--TLpAEDA1ggnXuw4/fWnNWUwcoOjLemhOvml1juMl5lhLmY5sBUsj8EWEAfL2gdeD9g8VDw5tgcxCiHGlEb67BgU2DlFzZApi4LheLJraA+pYjTGChVhpZz1iyiBPD+U2qxDQAbM3+WFY0EBlggxmVqG53Hu0Rg+KmHJFMlUhfgzo+AQP6+Kk9GzvJJOs4-k36RdoSFqaoARfQo0UncHAV0t3YTqrkD5r/z2jTrE43GZWobnce7RGD4qYckUyVSF+DOj4BA/r4qT0bO8kk6zg", nil)
	if want := "tskey-auth-k7UagY1CNTRL-ZZZZZ"; k != want {
		t.Errorf("decodeWrappedAuthkey(<wrapped-key>).key = %q, want %q", k, want)
	}
	if !isWrapped {
		t.Error("decodeWrappedAuthkey(<wrapped-key>).isWrapped = false, want true")
	}

	if sig == nil {
		t.Fatal("decodeWrappedAuthkey(<wrapped-key>).sig = nil, want non-nil signature")
	}
	sigHash := sig.SigHash()
	if !ed25519.Verify(sig.KeyID, sigHash[:], sig.Signature) {
		t.Error("signature failed to verify")
	}

	// Make sure the private is correct by using it.
	someSig := ed25519.Sign(priv, []byte{1, 2, 3, 4})
	if !ed25519.Verify(sig.WrappingPubkey, []byte{1, 2, 3, 4}, someSig) {
		t.Error("failed to use priv")
	}

}

func TestResignNKS(t *testing.T) {
	// Tailnet Lock keypair of a signing node.
	authPub, authPriv := testingKey25519(t, 1)
	authKey := Key{Kind: Key25519, Public: authPub, Votes: 2}

	// Node's own tailnet lock key used to sign rotation signatures.
	tlPriv := key.NewNLPrivate()

	// The original (oldest) node key, signed by a signing node.
	origNode := key.NewNode()
	origPub, _ := origNode.Public().MarshalBinary()

	// The original signature for the old node key, signed by
	// the network-lock key.
	directSig := NodeKeySignature{
		SigKind:        SigDirect,
		KeyID:          authKey.MustID(),
		Pubkey:         origPub,
		WrappingPubkey: tlPriv.Public().Verifier(),
	}
	sigHash := directSig.SigHash()
	directSig.Signature = ed25519.Sign(authPriv, sigHash[:])
	if err := directSig.verifySignature(origNode.Public(), authKey); err != nil {
		t.Fatalf("verifySignature(origNode) failed: %v", err)
	}

	// Generate a bunch of node keys to be used by tests.
	var nodeKeys []key.NodePublic
	for range 20 {
		n := key.NewNode()
		nodeKeys = append(nodeKeys, n.Public())
	}

	// mkSig creates a signature chain starting with a direct signature
	// with rotation signatures matching provided keys (from the nodeKeys slice).
	mkSig := func(prevKeyIDs ...int) tkatype.MarshaledSignature {
		sig := &directSig
		for _, i := range prevKeyIDs {
			pk, _ := nodeKeys[i].MarshalBinary()
			sig = &NodeKeySignature{
				SigKind: SigRotation,
				Pubkey:  pk,
				Nested:  sig,
			}
			var err error
			sig.Signature, err = tlPriv.SignNKS(sig.SigHash())
			if err != nil {
				t.Error(err)
			}
		}
		return sig.Serialize()
	}

	tests := []struct {
		name             string
		oldSig           tkatype.MarshaledSignature
		wantPrevNodeKeys []key.NodePublic
	}{
		{
			name:             "first-rotation",
			oldSig:           directSig.Serialize(),
			wantPrevNodeKeys: []key.NodePublic{origNode.Public()},
		},
		{
			name:             "second-rotation",
			oldSig:           mkSig(0),
			wantPrevNodeKeys: []key.NodePublic{nodeKeys[0], origNode.Public()},
		},
		{
			name:   "truncate-chain",
			oldSig: mkSig(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14),
			wantPrevNodeKeys: []key.NodePublic{
				nodeKeys[14],
				nodeKeys[13],
				nodeKeys[12],
				nodeKeys[11],
				nodeKeys[10],
				nodeKeys[9],
				nodeKeys[8],
				nodeKeys[7],
				nodeKeys[6],
				nodeKeys[5],
				nodeKeys[4],
				nodeKeys[3],
				nodeKeys[2],
				nodeKeys[1],
				origNode.Public(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newNode := key.NewNode()
			got, err := ResignNKS(tlPriv, newNode.Public(), tt.oldSig)
			if err != nil {
				t.Fatalf("ResignNKS() error = %v", err)
			}
			var gotSig NodeKeySignature
			if err := gotSig.Unserialize(got); err != nil {
				t.Fatalf("Unserialize() failed: %v", err)
			}
			if err := gotSig.verifySignature(newNode.Public(), authKey); err != nil {
				t.Errorf("verifySignature(newNode) error: %v", err)
			}

			rd, err := gotSig.rotationDetails()
			if err != nil {
				t.Fatalf("rotationDetails() error = %v", err)
			}
			if sigChainLength(gotSig) != len(tt.wantPrevNodeKeys)+1 {
				t.Errorf("sigChainLength() = %v, want %v", sigChainLength(gotSig), len(tt.wantPrevNodeKeys)+1)
			}
			if diff := cmp.Diff(tt.wantPrevNodeKeys, rd.PrevNodeKeys, cmpopts.EquateComparable(key.NodePublic{})); diff != "" {
				t.Errorf("PrevNodeKeys mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func sigChainLength(s NodeKeySignature) int {
	if s.Nested != nil {
		return 1 + sigChainLength(*s.Nested)
	}
	return 1
}
