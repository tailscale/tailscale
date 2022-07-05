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
	"golang.org/x/crypto/blake2s"
)

// AUMHash represents the BLAKE2s digest of an Authority Update Message (AUM).
type AUMHash [blake2s.Size]byte

// AUMSigHash represents the BLAKE2s digest of an Authority Update
// Message (AUM), sans any signatures.
type AUMSigHash [blake2s.Size]byte

// AUMKind describes valid AUM types.
type AUMKind uint8

// Valid AUM types. Do NOT reorder.
const (
	AUMInvalid AUMKind = iota
	// An AddKey AUM describes a new key trusted by the TKA.
	//
	// Only the Key optional field may be set.
	AUMAddKey
	// A RemoveKey AUM describes hte removal of a key trusted by TKA.
	//
	// Only the KeyID optional field may be set.
	AUMRemoveKey
	// A DisableNL AUM describes the disablement of TKA.
	//
	// Only the DisablementSecret optional field may be set.
	AUMDisableNL
	// A NoOp AUM carries no information and is used in tests.
	AUMNoOp
	// A UpdateKey AUM updates the metadata or votes of an existing key.
	//
	// Only KeyID, along with either/or Meta or Votes optional fields
	// may be set.
	AUMUpdateKey
	// A Checkpoint AUM specifies the full state of the TKA.
	//
	// Only the State optional field may be set.
	AUMCheckpoint
)

func (k AUMKind) String() string {
	switch k {
	case AUMInvalid:
		return "invalid"
	case AUMAddKey:
		return "add-key"
	case AUMRemoveKey:
		return "remove-key"
	case AUMDisableNL:
		return "disable-nl"
	case AUMNoOp:
		return "no-op"
	case AUMCheckpoint:
		return "checkpoint"
	case AUMUpdateKey:
		return "update-key"
	default:
		return fmt.Sprintf("AUM?<%d>", int(k))
	}
}

// AUM describes an Authority Update Message.
//
// The rules for adding new types of AUMs (MessageKind):
// - CBOR key IDs must never be changed.
// - New AUM types must not change semantics that are manipulated by other
//   AUM types.
// - The serialization of existing data cannot change (in other words, if
//   an existing serialization test in aum_test.go fails, you need to try a
//   different approach).
//
// The rules for adding new fields are as follows:
// - Must all be optional.
// - An unset value must not result in serialization overhead. This is
//   necessary so the serialization of older AUMs stays the same.
// - New processing semantics of the new fields must be compatible with the
//   behavior of old clients (which will ignore the field).
// - No floats!
type AUM struct {
	MessageKind AUMKind `cbor:"1,keyasint"`
	PrevAUMHash []byte  `cbor:"2,keyasint"`

	// Key encodes a public key to be added to the key authority.
	// This field is used for AddKey AUMs.
	Key *Key `cbor:"3,keyasint,omitempty"`

	// KeyID references a public key which is part of the key authority.
	// This field is used for RemoveKey and UpdateKey AUMs.
	KeyID KeyID `cbor:"4,keyasint,omitempty"`

	// State describes the full state of the key authority.
	// This field is used for Checkpoint AUMs.
	// TODO(tom): Use type *State once a future PR brings in that type.
	State interface{} `cbor:"5,keyasint,omitempty"`

	// DisablementSecret is used to transmit a secret for disabling
	// the TKA.
	// This field is used for DisableNL AUMs.
	DisablementSecret []byte `cbor:"6,keyasint,omitempty"`

	// Votes and Meta describe properties of a key in the key authority.
	// These fields are used for UpdateKey AUMs.
	Votes *uint             `cbor:"7,keyasint,omitempty"`
	Meta  map[string]string `cbor:"8,keyasint,omitempty"`

	// Signatures lists the signatures over this AUM.
	// CBOR key 23 is the last key which can be encoded as a single byte.
	Signatures []Signature `cbor:"23,keyasint,omitempty"`
}

// StaticValidate returns a nil error if the AUM is well-formed.
func (a *AUM) StaticValidate() error {
	if a.Key != nil {
		if err := a.Key.StaticValidate(); err != nil {
			return err
		}
	}
	if a.PrevAUMHash != nil && len(a.PrevAUMHash) == 0 {
		return errors.New("absent parent must be represented by a nil slice")
	}
	for i, sig := range a.Signatures {
		if len(sig.KeyID) == 0 || len(sig.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("signature %d has missing keyID or malformed signature", i)
		}
	}

	// TODO(tom): Validate State once a future PR brings in that type.

	switch a.MessageKind {
	case AUMAddKey:
		if a.Key == nil {
			return errors.New("AddKey AUMs must contain a key")
		}
		if a.KeyID != nil || a.DisablementSecret != nil || a.State != nil || a.Votes != nil || a.Meta != nil {
			return errors.New("AddKey AUMs may only specify a Key")
		}
	case AUMRemoveKey:
		if len(a.KeyID) == 0 {
			return errors.New("RemoveKey AUMs must specify a key ID")
		}
		if a.Key != nil || a.DisablementSecret != nil || a.State != nil || a.Votes != nil || a.Meta != nil {
			return errors.New("RemoveKey AUMs may only specify a KeyID")
		}
	case AUMUpdateKey:
		if len(a.KeyID) == 0 {
			return errors.New("UpdateKey AUMs must specify a key ID")
		}
		if a.Meta == nil && a.Votes == nil {
			return errors.New("UpdateKey AUMs must contain an update to votes or key metadata")
		}
		if a.Key != nil || a.DisablementSecret != nil || a.State != nil {
			return errors.New("UpdateKey AUMs may only specify KeyID, Votes, and Meta")
		}
	case AUMCheckpoint:
		if a.State == nil {
			return errors.New("Checkpoint AUMs must specify the state")
		}
		if a.KeyID != nil || a.DisablementSecret != nil || a.Key != nil || a.Votes != nil || a.Meta != nil {
			return errors.New("Checkpoint AUMs may only specify State")
		}
	case AUMDisableNL:
		if len(a.DisablementSecret) == 0 {
			return errors.New("DisableNL AUMs must specify a disablement secret")
		}
		if a.KeyID != nil || a.State != nil || a.Key != nil || a.Votes != nil || a.Meta != nil {
			return errors.New("DisableNL AUMs may only a disablement secret")
		}
	}

	return nil
}

// Serialize returns the given AUM in a serialized format.
func (a *AUM) Serialize() []byte {
	// Why CBOR and not something like JSON?
	//
	// The main function of an AUM is to carry signed data. Signatures are
	// over digests, so the serialized representation must be deterministic.
	// Further, experience with other attempts (JWS/JWT,SAML,X509 etc) has
	// taught us that even subtle behaviors such as how you handle invalid
	// or unrecognized fields + any invariants in subsequent re-serialization
	// can easily lead to security-relevant logic bugs. Its certainly possible
	// to invent a workable scheme by massaging a JSON parsing library, though
	// profoundly unwise.
	//
	// CBOR is one of the few encoding schemes that are appropriate for use
	// with signatures and has security-conscious parsing + serialization
	// rules baked into the spec. We use the CTAP2 mode, which is well
	// understood + widely-implemented, and already proven for use in signing
	// assertions through its use by FIDO2 devices.
	out := bytes.NewBuffer(make([]byte, 0, 128))
	encoder, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		// Deterministic validation of encoding options, should
		// never fail.
		panic(err)
	}
	if err := encoder.NewEncoder(out).Encode(a); err != nil {
		// Writing to a bytes.Buffer should never fail.
		panic(err)
	}
	return out.Bytes()
}

// Hash returns a cryptographic digest of all AUM contents.
func (a *AUM) Hash() AUMHash {
	return blake2s.Sum256(a.Serialize())
}

// SigHash returns the cryptographic digest which a signature
// is over.
//
// This is identical to Hash() except the Signatures are not
// serialized. Without this, the hash used for signatures
// would be circularly dependent on the signatures.
func (a AUM) SigHash() AUMSigHash {
	dupe := a
	dupe.Signatures = nil
	return blake2s.Sum256(dupe.Serialize())
}

// Parent returns the parent's AUM hash and true, or a
// zero value and false if there was no parent.
func (a *AUM) Parent() (h AUMHash, ok bool) {
	if len(a.PrevAUMHash) > 0 {
		copy(h[:], a.PrevAUMHash)
		return h, true
	}
	return h, false
}

func (a *AUM) sign25519(priv ed25519.PrivateKey) {
	key := Key{Kind: Key25519, Public: priv.Public().(ed25519.PublicKey)}
	sigHash := a.SigHash()

	a.Signatures = append(a.Signatures, Signature{
		KeyID:     key.ID(),
		Signature: ed25519.Sign(priv, sigHash[:]),
	})
}

// TODO(tom): Implement Weight() once a future PR brings in the State type.
