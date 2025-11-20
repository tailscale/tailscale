// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tka

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/hdevalence/ed25519consensus"
	"golang.org/x/crypto/blake2s"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/tkatype"
)

//go:generate go run tailscale.com/cmd/cloner  -clonefunc=false -type=NodeKeySignature

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

// String returns a human-readable representation of the NodeKeySignature,
// making it easy to see nested signatures.
func (s NodeKeySignature) String() string {
	var b strings.Builder
	var addToBuf func(NodeKeySignature, int)
	addToBuf = func(sig NodeKeySignature, depth int) {
		indent := strings.Repeat("  ", depth)
		b.WriteString(indent + "SigKind: " + sig.SigKind.String() + "\n")
		if len(sig.Pubkey) > 0 {
			var pubKey string
			var np key.NodePublic
			if err := np.UnmarshalBinary(sig.Pubkey); err != nil {
				pubKey = fmt.Sprintf("<error: %s>", err)
			} else {
				pubKey = np.ShortString()
			}
			b.WriteString(indent + "Pubkey: " + pubKey + "\n")
		}
		if len(sig.KeyID) > 0 {
			keyID := key.NLPublicFromEd25519Unsafe(sig.KeyID).CLIString()
			b.WriteString(indent + "KeyID: " + keyID + "\n")
		}
		if len(sig.WrappingPubkey) > 0 {
			pubKey := key.NLPublicFromEd25519Unsafe(sig.WrappingPubkey).CLIString()
			b.WriteString(indent + "WrappingPubkey: " + pubKey + "\n")
		}
		if sig.Nested != nil {
			b.WriteString(indent + "Nested:\n")
			addToBuf(*sig.Nested, depth+1)
		}
	}
	addToBuf(s, 0)
	return strings.TrimSpace(b.String())
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
		// key, so there's no need to check the node key.
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

// RotationDetails holds additional information about a nodeKeySignature
// of kind SigRotation.
type RotationDetails struct {
	// PrevNodeKeys is a list of node keys which have been rotated out.
	PrevNodeKeys []key.NodePublic

	// InitialSig is the first signature in the chain which led to
	// this rotating signature.
	InitialSig *NodeKeySignature
}

// rotationDetails returns the RotationDetails for a SigRotation signature.
func (s *NodeKeySignature) rotationDetails() (*RotationDetails, error) {
	if s.SigKind != SigRotation {
		return nil, nil
	}

	sri := &RotationDetails{}
	nested := s.Nested
	for nested != nil {
		if len(nested.Pubkey) > 0 {
			var nestedPub key.NodePublic
			if err := nestedPub.UnmarshalBinary(nested.Pubkey); err != nil {
				return nil, fmt.Errorf("nested pubkey: %v", err)
			}
			sri.PrevNodeKeys = append(sri.PrevNodeKeys, nestedPub)
		}
		if nested.SigKind != SigRotation {
			break
		}
		nested = nested.Nested
	}
	sri.InitialSig = nested
	return sri, nil
}

// ResignNKS re-signs a node-key signature for a new node-key.
//
// This only matters on network-locked tailnets, because node-key signatures are
// how other nodes know that a node-key is authentic. When the node-key is
// rotated then the existing signature becomes invalid, so this function is
// responsible for generating a new wrapping signature to certify the new node-key.
//
// The signature itself is a SigRotation signature, which embeds the old signature
// and certifies the new node-key as a replacement for the old by signing the new
// signature with RotationPubkey (which is the node's own network-lock key).
func ResignNKS(priv key.NLPrivate, nodeKey key.NodePublic, oldNKS tkatype.MarshaledSignature) (tkatype.MarshaledSignature, error) {
	var oldSig NodeKeySignature
	if err := oldSig.Unserialize(oldNKS); err != nil {
		return nil, fmt.Errorf("decoding NKS: %w", err)
	}

	nk, err := nodeKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalling node-key: %w", err)
	}

	if bytes.Equal(nk, oldSig.Pubkey) {
		// The old signature is valid for the node-key we are using, so just
		// use it verbatim.
		return oldNKS, nil
	}

	nested, err := maybeTrimRotationSignatureChain(oldSig, priv)
	if err != nil {
		return nil, fmt.Errorf("trimming rotation signature chain: %w", err)
	}

	newSig := NodeKeySignature{
		SigKind: SigRotation,
		Pubkey:  nk,
		Nested:  &nested,
	}
	if newSig.Signature, err = priv.SignNKS(newSig.SigHash()); err != nil {
		return nil, fmt.Errorf("signing NKS: %w", err)
	}

	return newSig.Serialize(), nil
}

// maybeTrimRotationSignatureChain truncates rotation signature chain to ensure
// it contains no more than 15 node keys.
func maybeTrimRotationSignatureChain(sig NodeKeySignature, priv key.NLPrivate) (NodeKeySignature, error) {
	if sig.SigKind != SigRotation {
		return sig, nil
	}

	// Collect all the previous node keys, ordered from newest to oldest.
	prevPubkeys := [][]byte{sig.Pubkey}
	nested := sig.Nested
	for nested != nil {
		if len(nested.Pubkey) > 0 {
			prevPubkeys = append(prevPubkeys, nested.Pubkey)
		}
		if nested.SigKind != SigRotation {
			break
		}
		nested = nested.Nested
	}

	// Existing rotation signature with 15 keys is the maximum we can wrap in a
	// new signature without hitting the CBOR nesting limit of 16 (see
	// MaxNestedLevels in tka.go).
	const maxPrevKeys = 15
	if len(prevPubkeys) <= maxPrevKeys {
		return sig, nil
	}

	// Create a new rotation signature chain, starting with the original
	// direct signature.
	var err error
	result := nested // original direct signature
	for i := maxPrevKeys - 2; i >= 0; i-- {
		result = &NodeKeySignature{
			SigKind: SigRotation,
			Pubkey:  prevPubkeys[i],
			Nested:  result,
		}
		if result.Signature, err = priv.SignNKS(result.SigHash()); err != nil {
			return sig, fmt.Errorf("signing NKS: %w", err)
		}
	}
	return *result, nil
}

// SignByCredential signs a node public key by a private key which has its
// signing authority delegated by a SigCredential signature. This is used by
// wrapped auth keys.
func SignByCredential(privKey []byte, wrapped *NodeKeySignature, nodeKey key.NodePublic) (tkatype.MarshaledSignature, error) {
	if wrapped.SigKind != SigCredential {
		return nil, fmt.Errorf("wrapped signature must be a credential, got %v", wrapped.SigKind)
	}

	nk, err := nodeKey.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshalling node-key: %w", err)
	}

	sig := &NodeKeySignature{
		SigKind: SigRotation,
		Pubkey:  nk,
		Nested:  wrapped,
	}
	sigHash := sig.SigHash()
	sig.Signature = ed25519.Sign(privKey, sigHash[:])
	return sig.Serialize(), nil
}

// DecodeWrappedAuthkey separates wrapping information from an authkey, if any.
// In all cases the authkey is returned, sans wrapping information if any.
//
// If the authkey is wrapped, isWrapped returns true, along with the wrapping signature
// and private key.
func DecodeWrappedAuthkey(wrappedAuthKey string, logf logger.Logf) (authKey string, isWrapped bool, sig *NodeKeySignature, priv ed25519.PrivateKey) {
	authKey, suffix, found := strings.Cut(wrappedAuthKey, "--TL")
	if !found {
		return wrappedAuthKey, false, nil, nil
	}
	sigBytes, privBytes, found := strings.Cut(suffix, "-")
	if !found {
		// TODO: propagate these errors to `tailscale up` output?
		logf("decoding wrapped auth-key: did not find delimiter")
		return wrappedAuthKey, false, nil, nil
	}

	rawSig, err := base64.RawStdEncoding.DecodeString(sigBytes)
	if err != nil {
		logf("decoding wrapped auth-key: signature decode: %v", err)
		return wrappedAuthKey, false, nil, nil
	}
	rawPriv, err := base64.RawStdEncoding.DecodeString(privBytes)
	if err != nil {
		logf("decoding wrapped auth-key: priv decode: %v", err)
		return wrappedAuthKey, false, nil, nil
	}

	sig = new(NodeKeySignature)
	if err := sig.Unserialize(rawSig); err != nil {
		logf("decoding wrapped auth-key: signature: %v", err)
		return wrappedAuthKey, false, nil, nil
	}
	priv = ed25519.PrivateKey(rawPriv)

	return authKey, true, sig, priv
}
