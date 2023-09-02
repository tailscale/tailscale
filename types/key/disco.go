// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"crypto/subtle"
	"fmt"

	"go4.org/mem"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"tailscale.com/types/structs"
)

const (
	// discoPublicHexPrefix is the prefix used to identify a
	// hex-encoded disco public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	discoPublicHexPrefix = "discokey:"

	// DiscoPublicRawLen is the length in bytes of a DiscoPublic, when
	// serialized with AppendTo, Raw32 or WriteRawWithoutAllocating.
	DiscoPublicRawLen = 32
)

// DiscoPrivate is a disco key, used for peer-to-peer path discovery.
type DiscoPrivate struct {
	_ structs.Incomparable // because == isn't constant-time
	k [32]byte
}

// NewDisco creates and returns a new disco private key.
func NewDisco() DiscoPrivate {
	var ret DiscoPrivate
	rand(ret.k[:])
	// Key used for nacl seal/open, so needs to be clamped.
	clamp25519Private(ret.k[:])
	return ret
}

// IsZero reports whether k is the zero value.
func (k DiscoPrivate) IsZero() bool {
	return k.Equal(DiscoPrivate{})
}

// Equal reports whether k and other are the same key.
func (k DiscoPrivate) Equal(other DiscoPrivate) bool {
	return subtle.ConstantTimeCompare(k.k[:], other.k[:]) == 1
}

// Public returns the DiscoPublic for k.
// Panics if DiscoPrivate is zero.
func (k DiscoPrivate) Public() DiscoPublic {
	if k.IsZero() {
		panic("can't take the public key of a zero DiscoPrivate")
	}
	var ret DiscoPublic
	curve25519.ScalarBaseMult(&ret.k, &k.k)
	return ret
}

// Shared returns the DiscoShared for communication between k and p.
func (k DiscoPrivate) Shared(p DiscoPublic) DiscoShared {
	if k.IsZero() || p.IsZero() {
		panic("can't compute shared secret with zero keys")
	}
	var ret DiscoShared
	box.Precompute(&ret.k, &p.k, &k.k)
	return ret
}

// DiscoPublic is the public portion of a DiscoPrivate.
type DiscoPublic struct {
	k [32]byte
}

// DiscoPublicFromRaw32 parses a 32-byte raw value as a DiscoPublic.
//
// This should be used only when deserializing a DiscoPublic from a
// binary protocol.
func DiscoPublicFromRaw32(raw mem.RO) DiscoPublic {
	if raw.Len() != 32 {
		panic("input has wrong size")
	}
	var ret DiscoPublic
	raw.Copy(ret.k[:])
	return ret
}

// IsZero reports whether k is the zero value.
func (k DiscoPublic) IsZero() bool {
	return k == DiscoPublic{}
}

// Raw32 returns k encoded as 32 raw bytes.
//
// Deprecated: only needed for a temporary compat shim in tailcfg, do
// not add more uses.
func (k DiscoPublic) Raw32() [32]byte {
	return k.k
}

// ShortString returns the Tailscale conventional debug representation
// of a disco key.
func (k DiscoPublic) ShortString() string {
	if k.IsZero() {
		return ""
	}
	return fmt.Sprintf("d:%x", k.k[:8])
}

// AppendTo appends k, serialized as a 32-byte binary value, to
// buf. Returns the new slice.
func (k DiscoPublic) AppendTo(buf []byte) []byte {
	return append(buf, k.k[:]...)
}

// String returns the output of MarshalText as a string.
func (k DiscoPublic) String() string {
	bs, err := k.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(bs)
}

// AppendText implements encoding.TextAppender.
func (k DiscoPublic) AppendText(b []byte) ([]byte, error) {
	return appendHexKey(b, discoPublicHexPrefix, k.k[:]), nil
}

// MarshalText implements encoding.TextMarshaler.
func (k DiscoPublic) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// MarshalText implements encoding.TextUnmarshaler.
func (k *DiscoPublic) UnmarshalText(b []byte) error {
	return parseHex(k.k[:], mem.B(b), mem.S(discoPublicHexPrefix))
}

type DiscoShared struct {
	_ structs.Incomparable // because == isn't constant-time
	k [32]byte
}

// Equal reports whether k and other are the same key.
func (k DiscoShared) Equal(other DiscoShared) bool {
	return subtle.ConstantTimeCompare(k.k[:], other.k[:]) == 1
}

func (k DiscoShared) IsZero() bool {
	return k.Equal(DiscoShared{})
}

// Seal wraps cleartext into a NaCl box (see
// golang.org/x/crypto/nacl), using k as the shared secret and a
// random nonce.
func (k DiscoShared) Seal(cleartext []byte) (ciphertext []byte) {
	if k.IsZero() {
		panic("can't seal with zero key")
	}
	var nonce [24]byte
	rand(nonce[:])
	return box.SealAfterPrecomputation(nonce[:], cleartext, &nonce, &k.k)
}

// Open opens the NaCl box ciphertext, which must be a value created
// by Seal, and returns the inner cleartext if ciphertext is a valid
// box using shared secret k.
func (k DiscoShared) Open(ciphertext []byte) (cleartext []byte, ok bool) {
	if k.IsZero() {
		panic("can't open with zero key")
	}
	if len(ciphertext) < 24 {
		return nil, false
	}
	nonce := (*[24]byte)(ciphertext)
	return box.OpenAfterPrecomputation(nil, ciphertext[24:], nonce, &k.k)
}
