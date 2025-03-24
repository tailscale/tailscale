// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go4.org/mem"
	"tailscale.com/types/structs"
)

var ErrInvalidMeshKey = errors.New("invalid mesh key")

// DERPMesh is a mesh key, used for inter-DERP-node communication and for
// privileged DERP clients.
type DERPMesh struct {
	_ structs.Incomparable // == isn't constant-time
	k [32]byte             // 64-digit hexadecimal numbers fit in 32 bytes
}

// MarshalJSON implements the [encoding/json.Marshaler] interface.
func (k DERPMesh) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON implements the [encoding/json.Unmarshaler] interface.
func (k *DERPMesh) UnmarshalJSON(data []byte) error {
	var s string
	json.Unmarshal(data, &s)

	if hex.DecodedLen(len(s)) != len(k.k) {
		return fmt.Errorf("types/key/derp: cannot unmarshal, incorrect size mesh key len: %d, must be %d, %w", hex.DecodedLen(len(s)), len(k.k), ErrInvalidMeshKey)
	}
	_, err := hex.Decode(k.k[:], []byte(s))
	if err != nil {
		return fmt.Errorf("types/key/derp: cannot unmarshal, invalid mesh key: %w", err)
	}

	return nil
}

// DERPMeshFromRaw32 parses a 32-byte raw value as a DERP mesh key.
func DERPMeshFromRaw32(raw mem.RO) DERPMesh {
	if raw.Len() != 32 {
		panic("input has wrong size")
	}
	var ret DERPMesh
	raw.Copy(ret.k[:])
	return ret
}

// ParseDERPMesh parses a DERP mesh key from a string.
// This function trims whitespace around the string.
// If the key is not a 64-digit hexadecimal number, ErrInvalidMeshKey is returned.
func ParseDERPMesh(key string) (DERPMesh, error) {
	key = strings.TrimSpace(key)
	if len(key) != 64 {
		return DERPMesh{}, fmt.Errorf("%w: must be 64-digit hexadecimal number", ErrInvalidMeshKey)
	}
	decoded, err := hex.DecodeString(key)
	if err != nil {
		return DERPMesh{}, fmt.Errorf("%w: %v", ErrInvalidMeshKey, err)
	}
	return DERPMeshFromRaw32(mem.B(decoded)), nil
}

// IsZero reports whether k is the zero value.
func (k DERPMesh) IsZero() bool {
	return k.Equal(DERPMesh{})
}

// Equal reports whether k and other are the same key.
func (k DERPMesh) Equal(other DERPMesh) bool {
	// Compare mesh keys in constant time to prevent timing attacks.
	// Since mesh keys are a fixed length, we don’t need to be concerned
	// about timing attacks on client mesh keys that are the wrong length.
	// See https://github.com/tailscale/corp/issues/28720
	return subtle.ConstantTimeCompare(k.k[:], other.k[:]) == 1
}

// String returns k as a hex-encoded 64-digit number.
func (k DERPMesh) String() string {
	return hex.EncodeToString(k.k[:])
}
