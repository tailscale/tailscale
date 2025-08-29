// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io"
)

var ErrUnsupported = fmt.Errorf("key type not supported on this platform")

const hardwareAttestPublicHexPrefix = "hwattestpub:"

// HardwareAttestationKey describes a hardware-backed key that is used to
// identify a node. Implementation details will
// vary based on the platform in use (SecureEnclave for Apple, TPM for
// Windows/Linux, Android Hardware-backed Keystore).
// This key can only be marshalled and unmarshalled on the same machine.
//
// NB: Due to fixed cryptographic primitives used in client platform
// implementations the "Sign" method should be passed a complete message and
// `nil` crypto.SignerOpts as all clients will compute a SHA256 digest of the
// message internally.
type HardwareAttestationKey interface {
	crypto.Signer
	json.Marshaler
	json.Unmarshaler
	io.Closer
	Clone() HardwareAttestationKey
}

func HardwareAttestationPublicFromPlatformKey(k HardwareAttestationKey) HardwareAttestationPublic {
	if k == nil {
		return HardwareAttestationPublic{}
	}
	pub := k.Public()
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		panic("hardware attestation key is not ECDSA")
	}
	bytes, err := ecdsaPub.Bytes()
	if err != nil {
		panic(err)
	}
	var kb [64]byte
	copy(kb[:], bytes)
	return HardwareAttestationPublic{k: kb}
}

// HardwareAttestationPublic is the public key counterpart to
// HardwareAttestationKey.
type HardwareAttestationPublic struct {
	k [64]byte
}

func (k HardwareAttestationPublic) Equal(o HardwareAttestationPublic) bool {
	return k.k == o.k
}

// IsZero reports whether k is the zero value.
func (k HardwareAttestationPublic) IsZero() bool {
	return k.k == [64]byte{}
}

// String returns the hex-encoded public key with a type prefix.
func (k HardwareAttestationPublic) String() string {
	bs, err := k.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(bs)
}

// MarshalText implements encoding.TextMarshaler.
func (k HardwareAttestationPublic) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k HardwareAttestationPublic) AppendText(dst []byte) ([]byte, error) {
	return appendHexKey(dst, hardwareAttestPublicHexPrefix, k.k[:]), nil
}

// Verifier returns the ECDSA public key for verifying signatures made by k.
func (k HardwareAttestationPublic) Verifier() *ecdsa.PublicKey {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), k.k[:])
	if err != nil {
		panic(err)
	}
	return pub
}

// emptyHardwareAttestationKey is a function that returns an empty
// HardwareAttestationKey suitable for use with JSON unmarshaling.
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
// suitable for JSON unmarshaling.
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
