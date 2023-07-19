// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	// SigCredential describes a signature over a specific public key, signed
	// by a key in the tailnet key authority referenced by the specified keyID.
	// In effect, SigCredential delegates the ability to make a signature to
	// a different public/private key pair.
	//
	// It is intended that a different public/private key pair be generated
	// for each different SigCredential that is created. Implementors must
	// take care that the private side is only known to the entity that needs
	// to generate the wrapping SigRotation signature, and it is immediately
	// discarded after use.
	//
	// SigCredential is expected to be nested in a SigRotation signature.
	SigCredential
)

func (s SigKind) String() string {
	switch s {
	case SigInvalid:
		return "invalid"
	case SigDirect:
		return "direct"
	case SigRotation:
		return "rotation"
	case SigCredential:
		return "credential"
	default:
		return fmt.Sprintf("Sig?<%d>", int(s))
	}
}

// NodeKeySignature encapsulates a signature that authorizes a specific
// node key, based on verification from keys in the tailnet key authority.
type NodeKeySignature struct {
	// SigKind identifies the variety of signature.
	SigKind SigKind `cbor:"1,keyasint"`
	// Pubkey identifies the key.NodePublic which is being authorized.
	// SigCredential signatures do not use this field.
	Pubkey []byte `cbor:"2,keyasint,omitempty"`

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

	// WrappingPubkey specifies the ed25519 public key which must be used
	// to sign a Signature which embeds this one.
	//
	// For SigRotation signatures multiple levels deep, intermediate
	// signatures may omit this value, in which case the parent WrappingPubkey
	// is used.
	//
	// SigCredential signatures use this field to specify the public key
	// they are certifying, following the usual semanticsfor WrappingPubkey.
	WrappingPubkey []byte `cbor:"6,keyasint,omitempty"`
}

// UnverifiedWrappingPublic returns the public key which must sign a
// signature which embeds this one, if any.
//
// See docs on NodeKeySignature.WrappingPubkey & SigRotation for documentation
// about wrapping public keys.
//
// SAFETY: The caller MUST verify the signature using
// Authority.NodeKeyAuthorized if treating this as authentic information.
func (s NodeKeySignature) UnverifiedWrappingPublic() (pub ed25519.PublicKey, ok bool) {
	return s.wrappingPublic()
}

// wrappingPublic returns the public key which must sign a signature which
// embeds this one, if any.
func (s NodeKeySignature) wrappingPublic() (pub ed25519.PublicKey, ok bool) {
	if len(s.WrappingPubkey) > 0 {
		return ed25519.PublicKey(s.WrappingPubkey), true
	}

	switch s.SigKind {
	case SigRotation:
		if s.Nested == nil {
			return nil, false
		}
		return s.Nested.wrappingPublic()

	default:
		return nil, false
	}
}

// UnverifiedAuthorizingKeyID returns the KeyID of the key which authorizes
// this signature.
//
// SAFETY: The caller MUST verify the signature using
// Authority.NodeKeyAuthorized if treating this as authentic information.
func (s NodeKeySignature) UnverifiedAuthorizingKeyID() (tkatype.KeyID, error) {
	return s.authorizingKeyID()
}

// authorizingKeyID returns the KeyID of the key trusted by network-lock which authorizes
// this signature.
func (s NodeKeySignature) authorizingKeyID() (tkatype.KeyID, error) {
	switch s.SigKind {
	case SigDirect, SigCredential:
		if len(s.KeyID) == 0 {
			return tkatype.KeyID{}, errors.New("invalid signature: no keyID present")
		}
		return tkatype.KeyID(s.KeyID), nil

	case SigRotation:
		if s.Nested == nil {
			return tkatype.KeyID{}, errors.New("invalid signature: rotation signature missing nested signature")
		}
		return s.Nested.authorizingKeyID()

	default:
		return tkatype.KeyID{}, fmt.Errorf("unhandled signature type: %v", s.SigKind)
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

// verifySignature checks that the NodeKeySignature is authentic & certified
// by the given verificationKey. Additionally, SigDirect and SigRotation
// signatures are checked to ensure they authorize the given nodeKey.
func (s *NodeKeySignature) verifySignature(nodeKey key.NodePublic, verificationKey Key) error {
	if s.SigKind != SigCredential {
		nodeBytes, err := nodeKey.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshalling pubkey: %v", err)
		}
		if !bytes.Equal(nodeBytes, s.Pubkey) {
			return errors.New("signature does not authorize nodeKey")
		}
	}

	sigHash := s.SigHash()
	switch s.SigKind {
	case SigRotation:
		if s.Nested == nil {
			return errors.New("nested signatures must nest a signature")
		}

		// Verify the signature using the nested rotation key.
		verifyPub, ok := s.Nested.wrappingPublic()
		if !ok {
			return errors.New("missing rotation key")
		}
		if len(verifyPub) != ed25519.PublicKeySize {
			return fmt.Errorf("bad rotation key length: %d", len(verifyPub))
		}
		if !ed25519.Verify(ed25519.PublicKey(verifyPub[:]), sigHash[:], s.Signature) {
			return errors.New("invalid signature")
		}

		// Recurse to verify the signature on the nested structure.
		var nestedPub key.NodePublic
		// SigCredential signatures certify an indirection key rather than a node
		// key, so theres no need to check the node key.
		if s.Nested.SigKind != SigCredential {
			if err := nestedPub.UnmarshalBinary(s.Nested.Pubkey); err != nil {
				return fmt.Errorf("nested pubkey: %v", err)
			}
		}
		if err := s.Nested.verifySignature(nestedPub, verificationKey); err != nil {
			return fmt.Errorf("nested: %v", err)
		}
		return nil

	case SigDirect, SigCredential:
		if s.Nested != nil {
			return fmt.Errorf("invalid signature: signatures of type %v cannot nest another signature", s.SigKind)
		}
		switch verificationKey.Kind {
		case Key25519:
			if len(verificationKey.Public) != ed25519.PublicKeySize {
				return fmt.Errorf("ed25519 key has wrong length: %d", len(verificationKey.Public))
			}
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
