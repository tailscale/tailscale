// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_tailnetlock

package tka

import (
	"crypto/ed25519"
	"errors"

	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/tkatype"
)

type Authority struct {
	head           AUM
	oldestAncestor AUM
	state          State
}

func (*Authority) Head() AUMHash { return AUMHash{} }

func (AUMHash) MarshalText() ([]byte, error) { return nil, errNoTailnetLock }

type State struct{}

// AUMKind describes valid AUM types.
type AUMKind uint8

type AUMHash [32]byte

type AUM struct {
	MessageKind AUMKind `cbor:"1,keyasint"`
	PrevAUMHash []byte  `cbor:"2,keyasint"`

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

type Chonk interface {
	// AUM returns the AUM with the specified digest.
	//
	// If the AUM does not exist, then os.ErrNotExist is returned.
	AUM(hash AUMHash) (AUM, error)

	// ChildAUMs returns all AUMs with a specified previous
	// AUM hash.
	ChildAUMs(prevAUMHash AUMHash) ([]AUM, error)

	// CommitVerifiedAUMs durably stores the provided AUMs.
	// Callers MUST ONLY provide AUMs which are verified (specifically,
	// a call to aumVerify() must return a nil error).
	// as the implementation assumes that only verified AUMs are stored.
	CommitVerifiedAUMs(updates []AUM) error

	// Heads returns AUMs for which there are no children. In other
	// words, the latest AUM in all possible chains (the 'leaves').
	Heads() ([]AUM, error)

	// SetLastActiveAncestor is called to record the oldest-known AUM
	// that contributed to the current state. This value is used as
	// a hint on next startup to determine which chain to pick when computing
	// the current state, if there are multiple distinct chains.
	SetLastActiveAncestor(hash AUMHash) error

	// LastActiveAncestor returns the oldest-known AUM that was (in a
	// previous run) an ancestor of the current state. This is used
	// as a hint to pick the correct chain in the event that the Chonk stores
	// multiple distinct chains.
	LastActiveAncestor() (*AUMHash, error)
}

// SigKind describes valid NodeKeySignature types.
type SigKind uint8

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

type DeeplinkValidationResult struct {
}

func (h *AUMHash) UnmarshalText(text []byte) error {
	return errNoTailnetLock
}

var errNoTailnetLock = errors.New("tailnet lock is not enabled")

func DecodeWrappedAuthkey(wrappedAuthKey string, logf logger.Logf) (authKey string, isWrapped bool, sig *NodeKeySignature, priv ed25519.PrivateKey) {
	return wrappedAuthKey, false, nil, nil
}

func ResignNKS(priv key.NLPrivate, nodeKey key.NodePublic, oldNKS tkatype.MarshaledSignature) (tkatype.MarshaledSignature, error) {
	return nil, nil
}

func SignByCredential(privKey []byte, wrapped *NodeKeySignature, nodeKey key.NodePublic) (tkatype.MarshaledSignature, error) {
	return nil, nil
}

func (s NodeKeySignature) String() string { return "" }
