// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"errors"

	"go4.org/mem"
	"tailscale.com/types/structs"
)

const (
	// chalPublicHexPrefix is the prefix used to identify a
	// hex-encoded challenge public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	chalPublicHexPrefix = "chalpub:"
)

// ChallengePrivate is a challenge key, used to test whether clients control a
// key they want to prove ownership of.
//
// A ChallengePrivate is ephemeral and not serialized to the disk or network.
type ChallengePrivate struct {
	_ structs.Incomparable // because == isn't constant-time
	k [32]byte
}

// NewChallenge creates and returns a new node private key.
func NewChallenge() ChallengePrivate {
	return ChallengePrivate(NewNode())
}

// Public returns the ChallengePublic for k.
// Panics if ChallengePublic is zero.
func (k ChallengePrivate) Public() ChallengePublic {
	pub := NodePrivate(k).Public()
	return ChallengePublic(pub)
}

// MarshalText implements encoding.TextMarshaler, but by returning an error.
// It shouldn't need to be marshalled anywhere.
func (k ChallengePrivate) MarshalText() ([]byte, error) {
	return nil, errors.New("refusing to marshal")
}

// SealToChallenge is like SealTo, but for a ChallengePublic.
func (k NodePrivate) SealToChallenge(p ChallengePublic, cleartext []byte) (ciphertext []byte) {
	return k.SealTo(NodePublic(p), cleartext)
}

// OpenFrom opens the NaCl box ciphertext, which must be a value
// created by NodePrivate.SealToChallenge, and returns the inner cleartext if
// ciphertext is a valid box from p to k.
func (k ChallengePrivate) OpenFrom(p NodePublic, ciphertext []byte) (cleartext []byte, ok bool) {
	return NodePrivate(k).OpenFrom(p, ciphertext)
}

// ChallengePublic is the public portion of a ChallengePrivate.
type ChallengePublic struct {
	k [32]byte
}

// String returns the output of MarshalText as a string.
func (k ChallengePublic) String() string {
	bs, err := k.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(bs)
}

// AppendText implements encoding.TextAppender.
func (k ChallengePublic) AppendText(b []byte) ([]byte, error) {
	return appendHexKey(b, chalPublicHexPrefix, k.k[:]), nil
}

// MarshalText implements encoding.TextMarshaler.
func (k ChallengePublic) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (k *ChallengePublic) UnmarshalText(b []byte) error {
	return parseHex(k.k[:], mem.B(b), mem.S(chalPublicHexPrefix))
}

// IsZero reports whether k is the zero value.
func (k ChallengePublic) IsZero() bool { return k == ChallengePublic{} }
