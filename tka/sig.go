// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tka

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/hdevalence/ed25519consensus"
	"golang.org/x/crypto/blake2s"
	"tailscale.com/types/tkatype"
)

// SigKind describes valid NodeKeySignature types.
type SigKind uint8

const (
	SigInvalid SigKind = iota
	// SigDirect describes a signature over a specific node key, using
	// the keyID specified.
	SigDirect
)

func (s SigKind) String() string {
	switch s {
	case SigInvalid:
		return "invalid"
	case SigDirect:
		return "direct"
	default:
		return fmt.Sprintf("Sig?<%d>", int(s))
	}
}

// NodeKeySignature encapsulates a signature that authorizes a specific
// node key, based on verification from keys in the tailnet key authority.
type NodeKeySignature struct {
	// SigKind identifies the variety of signature.
	SigKind SigKind `cbor:"1,keyasint"`
	// Pubkey identifies the public key which is being certified.
	Pubkey []byte `cbor:"2,keyasint"`

	// KeyID identifies which key in the tailnet key authority should
	// be used to verify this signature. Only set for SigDirect and
	// SigCredential signature kinds.
	KeyID []byte `cbor:"3,keyasint,omitempty"`

	// Signature is the packed (R, S) ed25519 signature over the rest
	// of the structure.
	Signature []byte `cbor:"4,keyasint,omitempty"`
}

// sigHash returns the cryptographic digest which a signature
// is over.
//
// This is a hash of the serialized structure, sans the signature.
// Without this exclusion, the hash used for the signature
// would be circularly dependent on the signature.
func (s NodeKeySignature) sigHash() [blake2s.Size]byte {
	dupe := s
	dupe.Signature = nil
	return blake2s.Sum256(dupe.Serialize())
}

// Serialize returns the given NKS in a serialized format.
func (s *NodeKeySignature) Serialize() tkatype.MarshaledSignature {
	out := bytes.NewBuffer(make([]byte, 0, 128)) // 64byte sig + 32byte keyID + 32byte headroom
	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		// Deterministic validation of encoding options, should
		// never fail.
		panic(err)
	}
	if err := encoder.NewEncoder(out).Encode(s); err != nil {
		// Writing to a bytes.Buffer should never fail.
		panic(err)
	}
	return out.Bytes()
}

// verifySignature checks that the NodeKeySignature is authentic and certified
// by the given verificationKey.
func (s *NodeKeySignature) verifySignature(verificationKey Key) error {
	sigHash := s.sigHash()
	switch verificationKey.Kind {
	case Key25519:
		if ed25519consensus.Verify(ed25519.PublicKey(verificationKey.Public), sigHash[:], s.Signature) {
			return nil
		}
		return errors.New("invalid signature")

	default:
		return fmt.Errorf("unhandled key type: %v", verificationKey.Kind)
	}
}
