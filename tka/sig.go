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
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// SigKind describes valid NodeKeySignature types.
type SigKind uint8

const (
	SigInvalid SigKind = iota
	// SigDirect describes a signature over a specific node key, signed
	// by a key in the tailnet key authority referenced by the specified keyID.
	SigDirect
	// SigRotation describes a signature over a specific node key, signed
	// by the rotation key authorized by a nested NodeKeySignature structure.
	//
	// While it is possible to nest rotations multiple times up to the CBOR
	// nesting limit, it is intended that nodes simply regenerate their outer
	// SigRotation signature and sign it again with their rotation key. That
	// way, SigRotation nesting should only be 2 deep in the common case.
	SigRotation
)

func (s SigKind) String() string {
	switch s {
	case SigInvalid:
		return "invalid"
	case SigDirect:
		return "direct"
	case SigRotation:
		return "rotation"
	default:
		return fmt.Sprintf("Sig?<%d>", int(s))
	}
}

// NodeKeySignature encapsulates a signature that authorizes a specific
// node key, based on verification from keys in the tailnet key authority.
type NodeKeySignature struct {
	// SigKind identifies the variety of signature.
	SigKind SigKind `cbor:"1,keyasint"`
	// Pubkey identifies the public key which is being authorized.
	Pubkey []byte `cbor:"2,keyasint"`

	// KeyID identifies which key in the tailnet key authority should
	// be used to verify this signature. Only set for SigDirect and
	// SigCredential signature kinds.
	KeyID []byte `cbor:"3,keyasint,omitempty"`

	// Signature is the packed (R, S) ed25519 signature over all other
	// fields of the structure.
	Signature []byte `cbor:"4,keyasint,omitempty"`

	// Nested describes a NodeKeySignature which authorizes the node-key
	// used as Pubkey. Only used for SigRotation signatures.
	Nested *NodeKeySignature `cbor:"5,keyasint,omitempty"`

	// RotationPubkey specifies the ed25519 public key which may sign a
	// SigRotation signature, which embeds this one.
	//
	// Intermediate SigRotation signatures may omit this value to use the
	// parent one.
	RotationPubkey []byte `cbor:"6,keyasint,omitempty"`
}

// rotationPublic returns the public key which must sign a SigRotation
// signature that embeds this signature, if any.
func (s NodeKeySignature) rotationPublic() (pub ed25519.PublicKey, ok bool) {
	if len(s.RotationPubkey) > 0 {
		return ed25519.PublicKey(s.RotationPubkey), true
	}

	switch s.SigKind {
	case SigRotation:
		if s.Nested == nil {
			return nil, false
		}
		return s.Nested.rotationPublic()

	default:
		return nil, false
	}
}

// SigHash returns the cryptographic digest which a signature
// is over.
//
// This is a hash of the serialized structure, sans the signature.
// Without this exclusion, the hash used for the signature
// would be circularly dependent on the signature.
func (s NodeKeySignature) SigHash() [blake2s.Size]byte {
	dupe := s
	dupe.Signature = nil
	return blake2s.Sum256(dupe.Serialize())
}

// Serialize returns the given NKS in a serialized format.
//
// We would implement encoding.BinaryMarshaler, except that would
// unfortunately get called by the cbor marshaller resulting in infinite
// recursion.
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

// Unserialize decodes bytes representing a marshaled NKS.
//
// We would implement encoding.BinaryUnmarshaler, except that would
// unfortunately get called by the cbor unmarshaller resulting in infinite
// recursion.
func (s *NodeKeySignature) Unserialize(data []byte) error {
	dec, _ := cborDecOpts.DecMode()
	return dec.Unmarshal(data, s)
}

// verifySignature checks that the NodeKeySignature is authentic, certified
// by the given verificationKey, and authorizes the given nodeKey.
func (s *NodeKeySignature) verifySignature(nodeKey key.NodePublic, verificationKey Key) error {
	nodeBytes, err := nodeKey.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshalling pubkey: %v", err)
	}
	if !bytes.Equal(nodeBytes, s.Pubkey) {
		return errors.New("signature does not authorize nodeKey")
	}

	sigHash := s.SigHash()
	switch s.SigKind {
	case SigRotation:
		if s.Nested == nil {
			return errors.New("nested signatures must nest a signature")
		}

		// Verify the signature using the nested rotation key.
		verifyPub, ok := s.Nested.rotationPublic()
		if !ok {
			return errors.New("missing rotation key")
		}
		if !ed25519.Verify(ed25519.PublicKey(verifyPub[:]), sigHash[:], s.Signature) {
			return errors.New("invalid signature")
		}

		// Recurse to verify the signature on the nested structure.
		var nestedPub key.NodePublic
		if err := nestedPub.UnmarshalBinary(s.Nested.Pubkey); err != nil {
			return fmt.Errorf("nested pubkey: %v", err)
		}
		if err := s.Nested.verifySignature(nestedPub, verificationKey); err != nil {
			return fmt.Errorf("nested: %v", err)
		}
		return nil

	case SigDirect:
		switch verificationKey.Kind {
		case Key25519:
			if ed25519consensus.Verify(ed25519.PublicKey(verificationKey.Public), sigHash[:], s.Signature) {
				return nil
			}
			return errors.New("invalid signature")

		default:
			return fmt.Errorf("unhandled key type: %v", verificationKey.Kind)
		}

	default:
		return fmt.Errorf("unhandled signature type: %v", s.SigKind)
	}
}
