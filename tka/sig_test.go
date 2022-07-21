// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"crypto/ed25519"
	"testing"
)

func TestSigDirect(t *testing.T) {
	nodeKeyPub := []byte{1, 2, 3, 4}

	// Verification key (the key used to sign)
	pub, priv := testingKey25519(t, 1)
	key := Key{Kind: Key25519, Public: pub, Votes: 2}

	sig := NodeKeySignature{
		SigKind: SigDirect,
		KeyID:   key.ID(),
		Pubkey:  nodeKeyPub,
	}
	sigHash := sig.sigHash()
	sig.Signature = ed25519.Sign(priv, sigHash[:])

	if sig.sigHash() != sigHash {
		t.Errorf("sigHash changed after signing: %x != %x", sig.sigHash(), sigHash)
	}

	if err := sig.verifySignature(key); err != nil {
		t.Fatalf("verifySignature() failed: %v", err)
	}
}
