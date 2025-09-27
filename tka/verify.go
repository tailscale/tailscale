// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tka

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/hdevalence/ed25519consensus"
	"tailscale.com/types/tkatype"
)

// signatureVerify returns a nil error if the signature is valid over the
// provided AUM BLAKE2s digest, using the given key.
func signatureVerify(s *tkatype.Signature, aumDigest tkatype.AUMSigHash, key Key) error {
	// NOTE(tom): Even if we can compute the public from the KeyID,
	//            its possible for the KeyID to be attacker-controlled
	//            so we should use the public contained in the state machine.
	switch key.Kind {
	case Key25519:
		if len(key.Public) != ed25519.PublicKeySize {
			return fmt.Errorf("ed25519 key has wrong length: %d", len(key.Public))
		}
		if ed25519consensus.Verify(ed25519.PublicKey(key.Public), aumDigest[:], s.Signature) {
			return nil
		}
		return errors.New("invalid signature")

	default:
		return fmt.Errorf("unhandled key type: %v", key.Kind)
	}
}
