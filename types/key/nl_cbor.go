// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package key

// The CBOR encoding/decoding for NLPublic is in a separate file because
// the plain type is used in tailscaled, but the CBOR encoding is only
// used in Tailnet Lock (aka Network Lock). We don't want to pull in the
// cbor dependency if you're not using Tailnet Lock.

import (
	"crypto/ed25519"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// MarshalCBOR implements the cbor.Marshaler interface.
//
// It marshals an NLPublic as if it was a byte slice using `keyasint`.
func (p NLPublic) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(p.k[:])
}

// UnmarshalCBOR implements the cbor.Unmarshaler interface.
//
// It unmarshals an NLPublic as if it was a byte slice using `keyasint`.
func (p *NLPublic) UnmarshalCBOR(data []byte) error {
	var buffer []byte

	if err := cbor.Unmarshal(data, &buffer); err != nil {
		return fmt.Errorf("unmarshal bytes: %v", err)
	}

	if len(buffer) != ed25519.PublicKeySize {
		return fmt.Errorf("expected %d bytes for NLPublic key, got %d", ed25519.PublicKeySize, len(buffer))
	}

	copy(p.k[:], buffer)

	return nil
}
