// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"

	"go4.org/mem"
)

var ErrUnsupported = fmt.Errorf("key type not supported on this platform")

const hardwareAttestPublicHexPrefix = "hwattestpub:"

const pubkeyLength = 65 // uncompressed P-256

// HardwareAttestationKey describes a hardware-backed key that is used to
// identify a node. Implementation details will
// vary based on the platform in use (SecureEnclave for Apple, TPM for
// Windows/Linux, Android Hardware-backed Keystore).
// This key can only be marshalled and unmarshaled on the same machine.
type HardwareAttestationKey interface {
	crypto.Signer
	json.Marshaler
	json.Unmarshaler
	io.Closer
	Clone() HardwareAttestationKey
	IsZero() bool
}

// HardwareAttestationPublicFromPlatformKey creates a HardwareAttestationPublic
// for communicating the public component of the hardware attestation key
// with control and other nodes.
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
	if len(bytes) != pubkeyLength {
		panic("hardware attestation key is not uncompressed ECDSA P-256")
	}
	var ecdsaPubArr [pubkeyLength]byte
	copy(ecdsaPubArr[:], bytes)
	return HardwareAttestationPublic{k: ecdsaPubArr}
}

// HardwareAttestationPublic is the public key counterpart to
// HardwareAttestationKey.
type HardwareAttestationPublic struct {
	k [pubkeyLength]byte
}

func (k *HardwareAttestationPublic) Clone() *HardwareAttestationPublic {
	if k == nil {
		return nil
	}
	var out HardwareAttestationPublic
	copy(out.k[:], k.k[:])
	return &out
}

func (k HardwareAttestationPublic) Equal(o HardwareAttestationPublic) bool {
	return subtle.ConstantTimeCompare(k.k[:], o.k[:]) == 1
}

// IsZero reports whether k is the zero value.
func (k HardwareAttestationPublic) IsZero() bool {
	var zero [pubkeyLength]byte
	return k.k == zero
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
	if k.IsZero() {
		return nil, nil
	}
	return k.AppendText(nil)
}

// UnmarshalText implements encoding.TextUnmarshaler. It expects a typed prefix
// followed by a hex encoded representation of k.
func (k *HardwareAttestationPublic) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*k = HardwareAttestationPublic{}
		return nil
	}

	kb := make([]byte, pubkeyLength)
	if err := parseHex(kb, mem.B(b), mem.S(hardwareAttestPublicHexPrefix)); err != nil {
		return err
	}

	_, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), kb)
	if err != nil {
		return err
	}
	copy(k.k[:], kb)
	return nil
}

func (k HardwareAttestationPublic) AppendText(dst []byte) ([]byte, error) {
	return appendHexKey(dst, hardwareAttestPublicHexPrefix, k.k[:]), nil
}

// Verifier returns the ECDSA public key for verifying signatures made by k.
func (k HardwareAttestationPublic) Verifier() *ecdsa.PublicKey {
	pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), k.k[:])
	if err != nil {
		panic(err)
	}
	return pk
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
