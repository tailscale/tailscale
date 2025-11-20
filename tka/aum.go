// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package tka

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base32"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2s"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/set"
)

// AUMHash represents the BLAKE2s digest of an Authority Update Message (AUM).
type AUMHash [blake2s.Size]byte

var base32StdNoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// String returns the AUMHash encoded as base32.
// This is suitable for use as a filename, and for storing in text-preferred media.
func (h AUMHash) String() string {
	return base32StdNoPad.EncodeToString(h[:])
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (h *AUMHash) UnmarshalText(text []byte) error {
	if ln := base32StdNoPad.DecodedLen(len(text)); ln != len(h) {
		return fmt.Errorf("tka.AUMHash.UnmarshalText: text wrong length: %d, want %d", ln, len(text))
	}
	if _, err := base32StdNoPad.Decode(h[:], text); err != nil {
		return fmt.Errorf("tka.AUMHash.UnmarshalText: %w", err)
	}
	return nil
}

// AppendText implements encoding.TextAppender.
func (h AUMHash) AppendText(b []byte) ([]byte, error) {
	return base32StdNoPad.AppendEncode(b, h[:]), nil
}

// MarshalText implements encoding.TextMarshaler.
func (h AUMHash) MarshalText() ([]byte, error) {
	return h.AppendText(nil)
}

// IsZero returns true if the hash is the empty value.
func (h AUMHash) IsZero() bool {
	return h == (AUMHash{})
}

// PrevAUMHash represents the BLAKE2s digest of an Authority Update Message (AUM).
// Unlike an AUMHash, this can be empty if there is no previous AUM hash
// (which occurs in the genesis AUM).
type PrevAUMHash []byte

// String returns the PrevAUMHash encoded as base32.
// This is suitable for use as a filename, and for storing in text-preferred media.
func (h PrevAUMHash) String() string {
	return base32StdNoPad.EncodeToString(h[:])
}

// AUMKind describes valid AUM types.
type AUMKind uint8

// Valid AUM types. Do NOT reorder.
const (
	AUMInvalid AUMKind = iota
	// An AddKey AUM describes a new key trusted by the TKA.
	//
	// Only the Key optional field may be set.
	AUMAddKey
	// A RemoveKey AUM describes the removal of a key trusted by TKA.
	//
	// Only the KeyID optional field may be set.
	AUMRemoveKey
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
//   - CBOR key IDs must never be changed.
//   - New AUM types must not change semantics that are manipulated by other
//     AUM types.
//   - The serialization of existing data cannot change (in other words, if
//     an existing serialization test in aum_test.go fails, you need to try a
//     different approach).
//
// The rules for adding new fields are as follows:
//   - Must all be optional.
//   - An unset value must not result in serialization overhead. This is
//     necessary so the serialization of older AUMs stays the same.
//   - New processing semantics of the new fields must be compatible with the
//     behavior of old clients (which will ignore the field).
//   - No floats!
type AUM struct {
	MessageKind AUMKind     `cbor:"1,keyasint"`
	PrevAUMHash PrevAUMHash `cbor:"2,keyasint"`

	// Key encodes a public key to be added to the key authority.
	// This field is used for AddKey AUMs.
	Key *Key `cbor:"3,keyasint,omitempty"`

	// KeyID references a public key which is part of the key authority.
	// This field is used for RemoveKey and UpdateKey AUMs.
	KeyID tkatype.KeyID `cbor:"4,keyasint,omitempty"`

	// State describes the full state of the key authority.
	// This field is used for Checkpoint AUMs.
	State *State `cbor:"5,keyasint,omitempty"`

	// Votes and Meta describe properties of a key in the key authority.
	// These fields are used for UpdateKey AUMs.
	Votes *uint             `cbor:"6,keyasint,omitempty"`
	Meta  map[string]string `cbor:"7,keyasint,omitempty"`

	// Signatures lists the signatures over this AUM.
	// CBOR key 23 is the last key which can be encoded as a single byte.
	Signatures []tkatype.Signature `cbor:"23,keyasint,omitempty"`
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
		if len(sig.KeyID) != 32 || len(sig.Signature) != ed25519.SignatureSize {
			return fmt.Errorf("signature %d has missing keyID or malformed signature", i)
		}
	}

	if a.State != nil {
		if err := a.State.staticValidateCheckpoint(); err != nil {
			return fmt.Errorf("checkpoint state: %v", err)
		}
	}

	switch a.MessageKind {
	case AUMAddKey:
		if a.Key == nil {
			return errors.New("AddKey AUMs must contain a key")
		}
		if a.KeyID != nil || a.State != nil || a.Votes != nil || a.Meta != nil {
			return errors.New("AddKey AUMs may only specify a Key")
		}
	case AUMRemoveKey:
		if len(a.KeyID) == 0 {
			return errors.New("RemoveKey AUMs must specify a key ID")
		}
		if a.Key != nil || a.State != nil || a.Votes != nil || a.Meta != nil {
			return errors.New("RemoveKey AUMs may only specify a KeyID")
		}
	case AUMUpdateKey:
		if len(a.KeyID) == 0 {
			return errors.New("UpdateKey AUMs must specify a key ID")
		}
		if a.Meta == nil && a.Votes == nil {
			return errors.New("UpdateKey AUMs must contain an update to votes or key metadata")
		}
		if a.Key != nil || a.State != nil {
			return errors.New("UpdateKey AUMs may only specify KeyID, Votes, and Meta")
		}
	case AUMCheckpoint:
		if a.State == nil {
			return errors.New("Checkpoint AUMs must specify the state")
		}
		if a.KeyID != nil || a.Key != nil || a.Votes != nil || a.Meta != nil {
			return errors.New("Checkpoint AUMs may only specify State")
		}

	case AUMNoOp:
	default:
		// An AUM with an unknown message kind was received! That means
		// that a future version of tailscaled added some feature we don't
		// understand.
		//
		// The future-compatibility contract for AUM message types is that
		// they must only add new features, not change the semantics of existing
		// mechanisms or features. As such, old clients can safely ignore them.
	}

	return nil
}

// Serialize returns the given AUM in a serialized format.
//
// We would implement encoding.BinaryMarshaler, except that would
// unfortunately get called by the cbor marshaller resulting in infinite
// recursion.
func (a *AUM) Serialize() tkatype.MarshaledAUM {
	// Why CBOR and not something like JSON?
	//
	// The main function of an AUM is to carry signed data. Signatures are
	// over digests, so the serialized representation must be deterministic.
	// Further, experience with other attempts (JWS/JWT,SAML,X509 etc) has
	// taught us that even subtle behaviors such as how you handle invalid
	// or unrecognized fields + any invariants in subsequent re-serialization
	// can easily lead to security-relevant logic bugs. It's certainly possible
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

// Unserialize decodes bytes representing a marshaled AUM.
//
// We would implement encoding.BinaryUnmarshaler, except that would
// unfortunately get called by the cbor unmarshaller resulting in infinite
// recursion.
func (a *AUM) Unserialize(data []byte) error {
	dec, _ := cborDecOpts.DecMode()
	return dec.Unmarshal(data, a)
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
func (a AUM) SigHash() tkatype.AUMSigHash {
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

func (a *AUM) sign25519(priv ed25519.PrivateKey) error {
	key := Key{Kind: Key25519, Public: priv.Public().(ed25519.PublicKey)}
	sigHash := a.SigHash()

	keyID, err := key.ID()
	if err != nil {
		return err
	}

	a.Signatures = append(a.Signatures, tkatype.Signature{
		KeyID:     keyID,
		Signature: ed25519.Sign(priv, sigHash[:]),
	})
	return nil
}

// Weight computes the 'signature weight' of the AUM
// based on keys in the state machine. The caller must
// ensure that all signatures are valid.
//
// More formally: W = Sum(key.votes)
//
// AUMs with a higher weight than their siblings
// are preferred when resolving forks in the AUM chain.
func (a *AUM) Weight(state State) uint {
	var weight uint

	// Track the keys that have already been used, so two
	// signatures with the same key do not result in 2x
	// the weight.
	//
	// Despite the wire encoding being []byte, all KeyIDs are
	// 32 bytes. As such, we use that as the key for the map,
	// because map keys cannot be slices.
	seenKeys := make(set.Set[[32]byte], 6)
	for _, sig := range a.Signatures {
		if len(sig.KeyID) != 32 {
			panic("unexpected: keyIDs are 32 bytes")
		}

		var keyID [32]byte
		copy(keyID[:], sig.KeyID)

		key, err := state.GetKey(sig.KeyID)
		if err != nil {
			if err == ErrNoSuchKey {
				// Signatures with an unknown key do not contribute
				// to the weight.
				continue
			}
			panic(err)
		}
		if seenKeys.Contains(keyID) {
			continue
		}

		weight += key.Votes
		seenKeys.Add(keyID)
	}

	return weight
}
