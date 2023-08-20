// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tkatype defines types for working with the tka package.
//
// Do not add extra dependencies to this package unless they are tiny,
// because this package encodes wire types that should be lightweight to use.
package tkatype

import "encoding/json"

// KeyID references a verification key stored in the key authority. A keyID
// uniquely identifies a key. KeyIDs are all 32 bytes.
//
// For 25519 keys: We just use the 32-byte public key.
//
// Even though this is a 32-byte value, we use a byte slice because
// CBOR-encoded byte slices have a different prefix to CBOR-encoded arrays.
// Encoding as a byte slice allows us to change the size in the future if we
// ever need to.
type KeyID []byte

// MarshaledSignature represents a marshaled tka.NodeKeySignature.
//
// While its underlying type is a string, it's just the raw signature bytes, not
// hex or base64, etc.
//
// Think of it as []byte, which it used to be. It's a string only to make it
// easier to use with cmd/viewer.
type MarshaledSignature string

func (a MarshaledSignature) MarshalJSON() ([]byte, error) {
	return json.Marshal([]byte(a))
}

func (a *MarshaledSignature) UnmarshalJSON(b []byte) error {
	var bs []byte
	if err := json.Unmarshal(b, &bs); err != nil {
		return err
	}
	*a = MarshaledSignature(bs)
	return nil
}

// MarshaledAUM represents a marshaled tka.AUM.
type MarshaledAUM []byte

// AUMSigHash represents the BLAKE2s digest of an Authority Update
// Message (AUM), sans any signatures.
type AUMSigHash [32]byte

// NKSSigHash represents the BLAKE2s digest of a Node-Key Signature (NKS),
// sans the Signature field if present.
type NKSSigHash [32]byte

// Signature describes a signature over an AUM, which can be verified
// using the key referenced by KeyID.
type Signature struct {
	KeyID     KeyID  `cbor:"1,keyasint"`
	Signature []byte `cbor:"2,keyasint"`
}
