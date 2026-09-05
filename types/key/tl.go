// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"crypto/ed25519"
	"crypto/subtle"

	"go4.org/mem"
	"tailscale.com/types/structs"
	"tailscale.com/types/tkatype"
)

const (
	// tlPrivateHexPrefix is the prefix used to identify a
	// hex-encoded tailnet-lock key.
	//
	// "nl" is a reference to "Network Lock", the pre-release name for
	// Tailnet Lock.
	tlPrivateHexPrefix = "nlpriv:"

	// tlPublicHexPrefix is the prefix used to identify the public
	// side of a hex-encoded tailnet-lock key.
	//
	// "nl" is a reference to "Network Lock", the pre-release name for
	// Tailnet Lock.
	tlPublicHexPrefix = "nlpub:"

	// tlPublicHexPrefixCLI is the prefix used for tailnet-lock keys
	// when shown on the CLI.
	// It's not practical for us to change the prefix everywhere due to
	// compatibility with existing clients, but we can support both prefixes
	// as well as use the CLI form when presenting to the user.
	tlPublicHexPrefixCLI = "tlpub:"
)

// TLPrivate is a node-managed tailnet-lock key, used for signing
// node-key signatures and authority update messages.
type TLPrivate struct {
	_ structs.Incomparable // because == isn't constant-time
	k [ed25519.PrivateKeySize]byte
}

// Deprecated: use [TLPrivate] instead.
type NLPrivate = TLPrivate

// IsZero reports whether k is the zero value.
func (k TLPrivate) IsZero() bool {
	empty := TLPrivate{}
	return subtle.ConstantTimeCompare(k.k[:], empty.k[:]) == 1
}

// NewTLPrivate creates and returns a new tailnet-lock key.
func NewTLPrivate() TLPrivate {
	// ed25519.GenerateKey 'clamps' the key, not that it
	// matters given we don't do Diffie-Hellman.
	_, priv, err := ed25519.GenerateKey(nil) // nil == crypto/rand
	if err != nil {
		panic(err)
	}

	var out TLPrivate
	copy(out.k[:], priv)
	return out
}

// Deprecated: use [NewTLPrivate] instead.
func NewNLPrivate() TLPrivate {
	return NewTLPrivate()
}

// MarshalText implements encoding.TextUnmarshaler.
func (k *TLPrivate) UnmarshalText(b []byte) error {
	return parseHex(k.k[:], mem.B(b), mem.S(tlPrivateHexPrefix))
}

// AppendText implements encoding.TextAppender.
func (k TLPrivate) AppendText(b []byte) ([]byte, error) {
	return appendHexKey(b, tlPrivateHexPrefix, k.k[:]), nil
}

// MarshalText implements encoding.TextMarshaler.
func (k TLPrivate) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// Equal reports whether k and other are the same key.
func (k TLPrivate) Equal(other TLPrivate) bool {
	return subtle.ConstantTimeCompare(k.k[:], other.k[:]) == 1
}

// Public returns the public component of this key.
func (k TLPrivate) Public() TLPublic {
	var out TLPublic
	copy(out.k[:], ed25519.PrivateKey(k.k[:]).Public().(ed25519.PublicKey))
	return out
}

// KeyID returns an identifier for this key.
func (k TLPrivate) KeyID() tkatype.KeyID {
	// The correct way to compute this is:
	// return tka.Key{
	// 	Kind:   tka.Key25519,
	// 	Public: pub.k[:],
	// }.ID()
	//
	// However, under the hood the key id for a 25519
	// key is just the public key, so we avoid the
	// dependency on tka by just doing this ourselves.
	pub := k.Public().k
	return pub[:]
}

// SignAUM implements tka.Signer.
func (k TLPrivate) SignAUM(sigHash tkatype.AUMSigHash) ([]tkatype.Signature, error) {
	return []tkatype.Signature{{
		KeyID:     k.KeyID(),
		Signature: ed25519.Sign(ed25519.PrivateKey(k.k[:]), sigHash[:]),
	}}, nil
}

// SignNKS signs the tka.NodeKeySignature identified by sigHash.
func (k TLPrivate) SignNKS(sigHash tkatype.NKSSigHash) ([]byte, error) {
	return ed25519.Sign(ed25519.PrivateKey(k.k[:]), sigHash[:]), nil
}

// TLPublic is the public portion of a [TLPrivate].
type TLPublic struct {
	k [ed25519.PublicKeySize]byte
}

// Deprecated: use [TLPublic] instead.
type NLPublic = TLPublic

// TLPublicFromEd25519Unsafe converts an ed25519 public key into
// a type of [TLPublic].
//
// New uses of this function should be avoided, as it's possible to
// accidentally construct an TLPublic from a non tailnet-lock key.
func TLPublicFromEd25519Unsafe(public ed25519.PublicKey) TLPublic {
	var out TLPublic
	copy(out.k[:], public)
	return out
}

// Deprecated: use [TLPublicFromEd25519Unsafe] instead.
func NLPublicFromEd25519Unsafe(public ed25519.PublicKey) TLPublic {
	return TLPublicFromEd25519Unsafe(public)
}

// UnmarshalText implements encoding.TextUnmarshaler. This function
// is able to decode both the CLI form (tlpub:<hex>) & the
// regular form (nlpub:<hex>).
func (k *TLPublic) UnmarshalText(b []byte) error {
	if mem.HasPrefix(mem.B(b), mem.S(tlPublicHexPrefix)) {
		return parseHex(k.k[:], mem.B(b), mem.S(tlPublicHexPrefix))
	}
	return parseHex(k.k[:], mem.B(b), mem.S(tlPublicHexPrefixCLI))
}

// AppendText implements encoding.TextAppender.
func (k TLPublic) AppendText(b []byte) ([]byte, error) {
	return appendHexKey(b, tlPublicHexPrefix, k.k[:]), nil
}

// MarshalText implements encoding.TextMarshaler, emitting a
// representation of the form nlpub:<hex>.
func (k TLPublic) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// CLIString returns a marshalled representation suitable for use
// with tailnet lock commands, of the form tlpub:<hex> instead of
// the nlpub:<hex> form emitted by MarshalText. Both forms can
// be decoded by UnmarshalText.
func (k TLPublic) CLIString() string {
	return string(appendHexKey(nil, tlPublicHexPrefixCLI, k.k[:]))
}

// Verifier returns a ed25519.PublicKey that can be used to
// verify signatures.
func (k TLPublic) Verifier() ed25519.PublicKey {
	return ed25519.PublicKey(k.k[:])
}

// IsZero reports whether k is the zero value.
func (k TLPublic) IsZero() bool {
	return k.Equal(TLPublic{})
}

// Equal reports whether k and other are the same key.
func (k TLPublic) Equal(other TLPublic) bool {
	return subtle.ConstantTimeCompare(k.k[:], other.k[:]) == 1
}

// KeyID returns a tkatype.KeyID that can be used with a tka.Authority.
func (k TLPublic) KeyID() tkatype.KeyID {
	return k.k[:]
}
