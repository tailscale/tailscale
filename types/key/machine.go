// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"

	"go4.org/mem"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"tailscale.com/types/structs"
)

const (
	// machinePrivateHexPrefix is the prefix used to identify a
	// hex-encoded machine private key.
	//
	// This prefix name is a little unfortunate, in that it comes from
	// WireGuard's own key types. Unfortunately we're stuck with it for
	// machine keys, because we serialize them to disk with this prefix.
	machinePrivateHexPrefix = "privkey:"

	// machinePublicHexPrefix is the prefix used to identify a
	// hex-encoded machine public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	machinePublicHexPrefix = "mkey:"
)

// MachinePrivate is a machine key, used for communication with the
// Tailscale coordination server.
type MachinePrivate struct {
	_ structs.Incomparable // == isn't constant-time
	k [32]byte
}

// NewMachine creates and returns a new machine private key.
func NewMachine() MachinePrivate {
	var ret MachinePrivate
	rand(ret.k[:])
	clamp25519Private(ret.k[:])
	return ret
}

// IsZero reports whether k is the zero value.
func (k MachinePrivate) IsZero() bool {
	return k.Equal(MachinePrivate{})
}

// Equal reports whether k and other are the same key.
func (k MachinePrivate) Equal(other MachinePrivate) bool {
	return subtle.ConstantTimeCompare(k.k[:], other.k[:]) == 1
}

// Public returns the MachinePublic for k.
// Panics if MachinePrivate is zero.
func (k MachinePrivate) Public() MachinePublic {
	if k.IsZero() {
		panic("can't take the public key of a zero MachinePrivate")
	}
	var ret MachinePublic
	curve25519.ScalarBaseMult(&ret.k, &k.k)
	return ret
}

// AppendText implements encoding.TextAppender.
func (k MachinePrivate) AppendText(b []byte) ([]byte, error) {
	return appendHexKey(b, machinePrivateHexPrefix, k.k[:]), nil
}

// MarshalText implements encoding.TextMarshaler.
func (k MachinePrivate) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// MarshalText implements encoding.TextUnmarshaler.
func (k *MachinePrivate) UnmarshalText(b []byte) error {
	return parseHex(k.k[:], mem.B(b), mem.S(machinePrivateHexPrefix))
}

// UntypedBytes returns k, encoded as an untyped 64-character hex
// string.
//
// Deprecated: this function is risky to use, because it produces
// serialized values that do not identify themselves as a
// MachinePrivate, allowing other code to potentially parse it back in
// as the wrong key type. For new uses that don't require this
// specific raw byte serialization, please use
// MarshalText/UnmarshalText.
func (k MachinePrivate) UntypedBytes() []byte {
	return bytes.Clone(k.k[:])
}

// SealTo wraps cleartext into a NaCl box (see
// golang.org/x/crypto/nacl) to p, authenticated from k, using a
// random nonce.
//
// The returned ciphertext is a 24-byte nonce concatenated with the
// box value.
func (k MachinePrivate) SealTo(p MachinePublic, cleartext []byte) (ciphertext []byte) {
	if k.IsZero() || p.IsZero() {
		panic("can't seal with zero keys")
	}
	var nonce [24]byte
	rand(nonce[:])
	return box.Seal(nonce[:], cleartext, &nonce, &p.k, &k.k)
}

// SharedKey returns the precomputed Nacl box shared key between k and p.
func (k MachinePrivate) SharedKey(p MachinePublic) MachinePrecomputedSharedKey {
	var shared MachinePrecomputedSharedKey
	box.Precompute(&shared.k, &p.k, &k.k)
	return shared
}

// MachinePrecomputedSharedKey is a precomputed shared NaCl box shared key.
type MachinePrecomputedSharedKey struct {
	k [32]byte
}

// Seal wraps cleartext into a NaCl box (see
// golang.org/x/crypto/nacl) using the shared key k as generated
// by MachinePrivate.SharedKey.
//
// The returned ciphertext is a 24-byte nonce concatenated with the
// box value.
func (k MachinePrecomputedSharedKey) Seal(cleartext []byte) (ciphertext []byte) {
	if k == (MachinePrecomputedSharedKey{}) {
		panic("can't seal with zero keys")
	}
	var nonce [24]byte
	rand(nonce[:])
	return box.SealAfterPrecomputation(nonce[:], cleartext, &nonce, &k.k)
}

// Open opens the NaCl box ciphertext, which must be a value created by
// MachinePrecomputedSharedKey.Seal or MachinePrivate.SealTo, and returns the
// inner cleartext if ciphertext is a valid box for the shared key k.
func (k MachinePrecomputedSharedKey) Open(ciphertext []byte) (cleartext []byte, ok bool) {
	if k == (MachinePrecomputedSharedKey{}) {
		panic("can't open with zero keys")
	}
	if len(ciphertext) < 24 {
		return nil, false
	}
	var nonce [24]byte
	copy(nonce[:], ciphertext)
	return box.OpenAfterPrecomputation(nil, ciphertext[len(nonce):], &nonce, &k.k)
}

// OpenFrom opens the NaCl box ciphertext, which must be a value
// created by SealTo, and returns the inner cleartext if ciphertext is
// a valid box from p to k.
func (k MachinePrivate) OpenFrom(p MachinePublic, ciphertext []byte) (cleartext []byte, ok bool) {
	if k.IsZero() || p.IsZero() {
		panic("can't open with zero keys")
	}
	if len(ciphertext) < 24 {
		return nil, false
	}
	var nonce [24]byte
	copy(nonce[:], ciphertext)
	return box.Open(nil, ciphertext[len(nonce):], &nonce, &p.k, &k.k)
}

// MachinePublic is the public portion of a a MachinePrivate.
type MachinePublic struct {
	k [32]byte
}

// MachinePublicFromRaw32 parses a 32-byte raw value as a MachinePublic.
//
// This should be used only when deserializing a MachinePublic from a
// binary protocol.
func MachinePublicFromRaw32(raw mem.RO) MachinePublic {
	if raw.Len() != 32 {
		panic("input has wrong size")
	}
	var ret MachinePublic
	raw.Copy(ret.k[:])
	return ret
}

// ParseMachinePublicUntyped parses an untyped 64-character hex value
// as a MachinePublic.
//
// Deprecated: this function is risky to use, because it cannot verify
// that the hex string was intended to be a MachinePublic. This can
// lead to accidentally decoding one type of key as another. For new
// uses that don't require backwards compatibility with the untyped
// string format, please use MarshalText/UnmarshalText.
func ParseMachinePublicUntyped(raw mem.RO) (MachinePublic, error) {
	var ret MachinePublic
	if err := parseHex(ret.k[:], raw, mem.B(nil)); err != nil {
		return MachinePublic{}, err
	}
	return ret, nil
}

// IsZero reports whether k is the zero value.
func (k MachinePublic) IsZero() bool {
	return k == MachinePublic{}
}

// ShortString returns the Tailscale conventional debug representation
// of a public key: the first five base64 digits of the key, in square
// brackets.
func (k MachinePublic) ShortString() string {
	return debug32(k.k)
}

// UntypedHexString returns k, encoded as an untyped 64-character hex
// string.
//
// Deprecated: this function is risky to use, because it produces
// serialized values that do not identify themselves as a
// MachinePublic, allowing other code to potentially parse it back in
// as the wrong key type. For new uses that don't require backwards
// compatibility with the untyped string format, please use
// MarshalText/UnmarshalText.
func (k MachinePublic) UntypedHexString() string {
	return hex.EncodeToString(k.k[:])
}

// UntypedBytes returns k, encoded as an untyped 64-character hex
// string.
//
// Deprecated: this function is risky to use, because it produces
// serialized values that do not identify themselves as a
// MachinePublic, allowing other code to potentially parse it back in
// as the wrong key type. For new uses that don't require this
// specific raw byte serialization, please use
// MarshalText/UnmarshalText.
func (k MachinePublic) UntypedBytes() []byte {
	return bytes.Clone(k.k[:])
}

// String returns the output of MarshalText as a string.
func (k MachinePublic) String() string {
	bs, err := k.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(bs)
}

// AppendText implements encoding.TextAppender.
func (k MachinePublic) AppendText(b []byte) ([]byte, error) {
	return appendHexKey(b, machinePublicHexPrefix, k.k[:]), nil
}

// MarshalText implements encoding.TextMarshaler.
func (k MachinePublic) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// MarshalText implements encoding.TextUnmarshaler.
func (k *MachinePublic) UnmarshalText(b []byte) error {
	return parseHex(k.k[:], mem.B(b), mem.S(machinePublicHexPrefix))
}
