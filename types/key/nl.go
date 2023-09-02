// Copyright (c) Tailscale Inc & AUTHORS
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
	// nlPrivateHexPrefix is the prefix used to identify a
	// hex-encoded tailnet-lock key.
	nlPrivateHexPrefix = "nlpriv:"

	// nlPublicHexPrefix is the prefix used to identify the public
	// side of a hex-encoded tailnet-lock key.
	nlPublicHexPrefix = "nlpub:"

	// nlPublicHexPrefixCLI is the prefix used for tailnet-lock keys
	// when shown on the CLI.
	// It's not practical for us to change the prefix everywhere due to
	// compatibility with existing clients, but we can support both prefixes
	// as well as use the CLI form when presenting to the user.
	nlPublicHexPrefixCLI = "tlpub:"
)

// NLPrivate is a node-managed network-lock key, used for signing
// node-key signatures and authority update messages.
type NLPrivate struct {
	_ structs.Incomparable // because == isn't constant-time
	k [ed25519.PrivateKeySize]byte
}

// IsZero reports whether k is the zero value.
func (k NLPrivate) IsZero() bool {
	empty := NLPrivate{}
	return subtle.ConstantTimeCompare(k.k[:], empty.k[:]) == 1
}

// NewNLPrivate creates and returns a new network-lock key.
func NewNLPrivate() NLPrivate {
	// ed25519.GenerateKey 'clamps' the key, not that it
	// matters given we don't do Diffie-Hellman.
	_, priv, err := ed25519.GenerateKey(nil) // nil == crypto/rand
	if err != nil {
		panic(err)
	}

	var out NLPrivate
	copy(out.k[:], priv)
	return out
}

// MarshalText implements encoding.TextUnmarshaler.
func (k *NLPrivate) UnmarshalText(b []byte) error {
	return parseHex(k.k[:], mem.B(b), mem.S(nlPrivateHexPrefix))
}

// AppendText implements encoding.TextAppender.
func (k NLPrivate) AppendText(b []byte) ([]byte, error) {
	return appendHexKey(b, nlPrivateHexPrefix, k.k[:]), nil
}

// MarshalText implements encoding.TextMarshaler.
func (k NLPrivate) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// Equal reports whether k and other are the same key.
func (k NLPrivate) Equal(other NLPrivate) bool {
	return subtle.ConstantTimeCompare(k.k[:], other.k[:]) == 1
}

// Public returns the public component of this key.
func (k NLPrivate) Public() NLPublic {
	var out NLPublic
	copy(out.k[:], ed25519.PrivateKey(k.k[:]).Public().(ed25519.PublicKey))
	return out
}

// KeyID returns an identifier for this key.
func (k NLPrivate) KeyID() tkatype.KeyID {
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
func (k NLPrivate) SignAUM(sigHash tkatype.AUMSigHash) ([]tkatype.Signature, error) {
	return []tkatype.Signature{{
		KeyID:     k.KeyID(),
		Signature: ed25519.Sign(ed25519.PrivateKey(k.k[:]), sigHash[:]),
	}}, nil
}

// SignNKS signs the tka.NodeKeySignature identified by sigHash.
func (k NLPrivate) SignNKS(sigHash tkatype.NKSSigHash) ([]byte, error) {
	return ed25519.Sign(ed25519.PrivateKey(k.k[:]), sigHash[:]), nil
}

// NLPublic is the public portion of a a NLPrivate.
type NLPublic struct {
	k [ed25519.PublicKeySize]byte
}

// NLPublicFromEd25519Unsafe converts an ed25519 public key into
// a type of NLPublic.
//
// New uses of this function should be avoided, as its possible to
// accidentally construct an NLPublic from a non network-lock key.
func NLPublicFromEd25519Unsafe(public ed25519.PublicKey) NLPublic {
	var out NLPublic
	copy(out.k[:], public)
	return out
}

// UnmarshalText implements encoding.TextUnmarshaler. This function
// is able to decode both the CLI form (tlpub:<hex>) & the
// regular form (nlpub:<hex>).
func (k *NLPublic) UnmarshalText(b []byte) error {
	if mem.HasPrefix(mem.B(b), mem.S(nlPublicHexPrefixCLI)) {
		return parseHex(k.k[:], mem.B(b), mem.S(nlPublicHexPrefixCLI))
	}
	return parseHex(k.k[:], mem.B(b), mem.S(nlPublicHexPrefix))
}

// AppendText implements encoding.TextAppender.
func (k NLPublic) AppendText(b []byte) ([]byte, error) {
	return appendHexKey(b, nlPublicHexPrefix, k.k[:]), nil
}

// MarshalText implements encoding.TextMarshaler, emitting a
// representation of the form nlpub:<hex>.
func (k NLPublic) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// CLIString returns a marshalled representation suitable for use
// with tailnet lock commands, of the form tlpub:<hex> instead of
// the nlpub:<hex> form emitted by MarshalText. Both forms can
// be decoded by UnmarshalText.
func (k NLPublic) CLIString() string {
	return string(appendHexKey(nil, nlPublicHexPrefixCLI, k.k[:]))
}

// Verifier returns a ed25519.PublicKey that can be used to
// verify signatures.
func (k NLPublic) Verifier() ed25519.PublicKey {
	return ed25519.PublicKey(k.k[:])
}

// IsZero reports whether k is the zero value.
func (k NLPublic) IsZero() bool {
	return k.Equal(NLPublic{})
}

// Equal reports whether k and other are the same key.
func (k NLPublic) Equal(other NLPublic) bool {
	return subtle.ConstantTimeCompare(k.k[:], other.k[:]) == 1
}

// KeyID returns a tkatype.KeyID that can be used with a tka.Authority.
func (k NLPublic) KeyID() tkatype.KeyID {
	return k.k[:]
}
