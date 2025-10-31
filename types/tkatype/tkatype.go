// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tkatype defines types for working with the tka package.
//
// Do not add extra dependencies to this package unless they are tiny,
// because this package encodes wire types that should be lightweight to use.
package tkatype

import (
	"bytes"
	"encoding/hex"
	jsonv1 "encoding/json"
	"fmt"
	"strings"
)

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

// MarshalJSON implements [jsonv1.MarshalJSON].
//
// We encode a key ID as a hex string starting `tlpub:`, unless it's empty,
// in which case we marshal it as JSON.
func (k KeyID) MarshalJSON() ([]byte, error) {
	if len(k) == 0 {
		return []byte("null"), nil
	}
	return jsonv1.Marshal(fmt.Sprintf("tlpub:%x", k))
}

// UnmarshalJSON implements [jsonv1.UnmarshalJSON].
func (k *KeyID) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		*k = []byte{}
		return nil
	}

	var s string
	if err := jsonv1.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("KeyID: cannot unmarshal non-string, non-null value: %w", err)
	}

	prefix := "tlpub:"
	if !strings.HasPrefix(s, prefix) {
		return fmt.Errorf("KeyID: missing required prefix %q in string %q", prefix, s)
	}

	hexData := s[len(prefix):]
	decoded, err := hex.DecodeString(hexData)
	if err != nil {
		return fmt.Errorf("KeyID: invalid hex encoding in string %q: %w", s, err)
	}

	*k = KeyID(decoded)
	return nil
}

// MarshaledSignature represents a marshaled tka.NodeKeySignature.
type MarshaledSignature []byte

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
