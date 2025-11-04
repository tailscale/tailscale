// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"sync/atomic"

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

// SortedPairOfDiscoPublic is a lexicographically sorted container of two
// [DiscoPublic] keys.
type SortedPairOfDiscoPublic struct {
	k [2]DiscoPublic
}

// Get returns the underlying keys.
func (s SortedPairOfDiscoPublic) Get() [2]DiscoPublic {
	return s.k
}

// NewSortedPairOfDiscoPublic returns a SortedPairOfDiscoPublic from a and b.
func NewSortedPairOfDiscoPublic(a, b DiscoPublic) SortedPairOfDiscoPublic {
	s := SortedPairOfDiscoPublic{}
	if a.Compare(b) < 0 {
		s.k[0] = a
		s.k[1] = b
	} else {
		s.k[0] = b
		s.k[1] = a
	}
	return s
}

func (s SortedPairOfDiscoPublic) String() string {
	return fmt.Sprintf("%s <=> %s", s.k[0].ShortString(), s.k[1].ShortString())
}

// Equal returns true if s and b are equal, otherwise it returns false.
func (s SortedPairOfDiscoPublic) Equal(b SortedPairOfDiscoPublic) bool {
	for i := range s.k {
		if s.k[i].Compare(b.k[i]) != 0 {
			return false
		}
	}
	return true
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

// Compare returns an integer comparing DiscoPublic k and l lexicographically.
// The result will be 0 if k == l, -1 if k < l, and +1 if k > l. This is useful
// for situations requiring only one node in a pair to perform some operation,
// e.g. probing UDP path lifetime.
func (k DiscoPublic) Compare(l DiscoPublic) int {
	return bytes.Compare(k.k[:], l.k[:])
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

type discoKeyPair struct {
	private DiscoPrivate
	public  DiscoPublic
	short   string
}

// DiscoKey is an atomic container for a disco private key, public key, and
// the public key's ShortString. The private and public keys are always kept
// synchronized.
//
// The zero value is not ready for use. Use NewDiscoKey or
// NewDiscoKeyFromPrivate to create a DiscoKey.
type DiscoKey struct {
	pair atomic.Pointer[discoKeyPair]
}

// NewDiscoKey creates and returns a new DiscoKey.
func NewDiscoKey() *DiscoKey {
	dk := &DiscoKey{}
	k := NewDisco()
	p := k.Public()
	dk.pair.Store(&discoKeyPair{
		private: k,
		public:  p,
		short:   p.ShortString(),
	})
	return dk
}

// NewDiscoKeyFromPrivate creates and returns a new DiscoKey from k.
func NewDiscoKeyFromPrivate(k DiscoPrivate) *DiscoKey {
	dk := &DiscoKey{}
	p := k.Public()
	dk.pair.Store(&discoKeyPair{
		private: k,
		public:  p,
		short:   p.ShortString(),
	})
	return dk
}

// Pair returns the private and public keys together atomically.
// Code that needs both the private and public keys synchronized should
// use Pair instead of calling Private and Public separately.
func (dk *DiscoKey) Pair() (private DiscoPrivate, public DiscoPublic) {
	p := dk.pair.Load()
	return p.private, p.public
}

// Private returns the private key.
func (dk *DiscoKey) Private() DiscoPrivate {
	return dk.pair.Load().private
}

// Public returns the public key.
func (dk *DiscoKey) Public() DiscoPublic {
	return dk.pair.Load().public
}

// Short returns the short string of the public key (see DiscoPublic.ShortString).
func (dk *DiscoKey) Short() string {
	return dk.pair.Load().short
}

// Set updates the private key (and the cached public key and short string).
func (dk *DiscoKey) Set(private DiscoPrivate) {
	public := private.Public()
	dk.pair.Store(&discoKeyPair{
		private: private,
		public:  public,
		short:   public.ShortString(),
	})
}
