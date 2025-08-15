// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"crypto"
	"encoding/json"
	"fmt"
)

var ErrUnsupported = fmt.Errorf("key type not supported on this platform")

// HardwareAttestationKey describes a hardware-backed key that is used to
// identify a node. Implementation details will
// vary based on the platform in use (SecureEnclave for Apple, TPM for
// Windows/Linux, Android Hardware-backed Keystore).
// This key can only be marshalled and unmarshalled on the same machine.
type HardwareAttestationKey interface {
	crypto.Signer
	json.Marshaler
	json.Unmarshaler
}

// emptyHardwareAttestationKey is a function that returns an empty
// HardwareAttestationKey suitable for use with JSON unmarshalling.
var emptyHardwareAttestationKey func() HardwareAttestationKey

// createHardwareAttestationKey is a function that creates a new
// HardwareAttestationKey for the current platform.
var createHardwareAttestationKey func() (HardwareAttestationKey, error)

// HardwareAttestationKeyFn is a callback function type that returns a HardwareAttestationKey
// and an error. It is used to register platform-specific implementations of
// HardwareAttestationKey.
type HardwareAttestationKeyFn func() (HardwareAttestationKey, error)

// RegisterHardwareAttestationKeyFns registers a hardware attestation
// key implementation for the current platform.
func RegisterHardwareAttestationKeyFns(emptyFn func() HardwareAttestationKey, createFn HardwareAttestationKeyFn) {
	if emptyHardwareAttestationKey != nil {
		panic("emptyPlatformHardwareAttestationKey already registered")
	}
	emptyHardwareAttestationKey = emptyFn

	if createHardwareAttestationKey != nil {
		panic("createPlatformHardwareAttestationKey already registered")
	}
	createHardwareAttestationKey = createFn
}

// NewEmptyHardwareAttestationKey returns an empty HardwareAttestationKey
// suitable for JSON unmarshalling.
func NewEmptyHardwareAttestationKey() (HardwareAttestationKey, error) {
	if emptyHardwareAttestationKey == nil {
		return nil, ErrUnsupported
	}
	return emptyHardwareAttestationKey(), nil
}

// NewHardwareAttestationKey returns a newly created HardwareAttestationKey for
// the current platform.
func NewHardwareAttestationKey() (HardwareAttestationKey, error) {
	if createHardwareAttestationKey == nil {
		return nil, ErrUnsupported
	}
	return createHardwareAttestationKey()
}
