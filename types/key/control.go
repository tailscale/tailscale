// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import "encoding/json"

// ControlPrivate is a Tailscale control plane private key.
//
// It is functionally equivalent to a MachinePrivate, but serializes
// to JSON as a byte array rather than a typed string, because our
// control plane database stores the key that way.
//
// Deprecated: this type should only be used in Tailscale's control
// plane, where existing database serializations require this
// less-good serialization format to persist. Other control plane
// implementations can use MachinePrivate with no downsides.
type ControlPrivate struct {
	mkey MachinePrivate // unexported so we can limit the API surface to only exactly what we need
}

// NewControl generates and returns a new control plane private key.
func NewControl() ControlPrivate {
	return ControlPrivate{NewMachine()}
}

// IsZero reports whether k is the zero value.
func (k ControlPrivate) IsZero() bool {
	return k.mkey.IsZero()
}

// Public returns the MachinePublic for k.
// Panics if ControlPrivate is zero.
func (k ControlPrivate) Public() MachinePublic {
	return k.mkey.Public()
}

// MarshalJSON implements json.Marshaler.
func (k ControlPrivate) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.mkey.k)
}

// UnmarshalJSON implements json.Unmarshaler.
func (k *ControlPrivate) UnmarshalJSON(bs []byte) error {
	return json.Unmarshal(bs, &k.mkey.k)
}

// SealTo wraps cleartext into a NaCl box (see
// golang.org/x/crypto/nacl) to p, authenticated from k, using a
// random nonce.
//
// The returned ciphertext is a 24-byte nonce concatenated with the
// box value.
func (k ControlPrivate) SealTo(p MachinePublic, cleartext []byte) (ciphertext []byte) {
	return k.mkey.SealTo(p, cleartext)
}

// SharedKey returns the precomputed Nacl box shared key between k and p.
func (k ControlPrivate) SharedKey(p MachinePublic) MachinePrecomputedSharedKey {
	return k.mkey.SharedKey(p)
}

// OpenFrom opens the NaCl box ciphertext, which must be a value
// created by SealTo, and returns the inner cleartext if ciphertext is
// a valid box from p to k.
func (k ControlPrivate) OpenFrom(p MachinePublic, ciphertext []byte) (cleartext []byte, ok bool) {
	return k.mkey.OpenFrom(p, ciphertext)
}
