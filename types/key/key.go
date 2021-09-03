// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package key defines some types for the various keys Tailscale uses.
package key

import (
	"encoding/base64"
	"errors"
	"fmt"

	"go4.org/mem"
	"golang.org/x/crypto/curve25519"
)

// Private represents a curve25519 private key of unspecified purpose.
//
// Deprecated: this key type has been used for several different
// keypairs, which are used in different protocols. This makes it easy
// to accidentally use the wrong key for a particular purpose, because
// the type system doesn't protect you. Please define dedicated key
// types for each purpose (e.g. communication with control, disco,
// wireguard...) instead, even if they are a Curve25519 value under
// the hood.
type Private [32]byte

// Private reports whether p is the zero value.
func (p Private) IsZero() bool { return p == Private{} }

// NewPrivate returns a new private key.
func NewPrivate() Private {
	var p Private
	rand(p[:])
	clamp25519Private(p[:])
	return p
}

// B32 returns k as the *[32]byte type that's used by the
// golang.org/x/crypto packages. This allocates; it might
// not be appropriate for performance-sensitive paths.
func (k Private) B32() *[32]byte { return (*[32]byte)(&k) }

// Public represents a curve25519 public key.
//
// Deprecated: this key type has been used for several different
// keypairs, which are used in different protocols. This makes it easy
// to accidentally use the wrong key for a particular purpose, because
// the type system doesn't protect you. Please define dedicated key
// types for each purpose (e.g. communication with control, disco,
// wireguard...) instead, even if they are a Curve25519 value under
// the hood.
type Public [32]byte

// Public reports whether p is the zero value.
func (p Public) IsZero() bool { return p == Public{} }

// ShortString returns the Tailscale conventional debug representation
// of a public key: the first five base64 digits of the key, in square
// brackets.
func (p Public) ShortString() string {
	return "[" + base64.StdEncoding.EncodeToString(p[:])[:5] + "]"
}

func (p Public) MarshalText() ([]byte, error) {
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(p)))
	base64.StdEncoding.Encode(buf, p[:])
	return buf, nil
}

func (p *Public) UnmarshalText(txt []byte) error {
	if *p != (Public{}) {
		return errors.New("refusing to unmarshal into non-zero key.Public")
	}
	n, err := base64.StdEncoding.Decode(p[:], txt)
	if err != nil {
		return err
	}
	if n != 32 {
		return fmt.Errorf("short decode of %d; want 32", n)
	}
	return nil
}

// B32 returns k as the *[32]byte type that's used by the
// golang.org/x/crypto packages. This allocates; it might
// not be appropriate for performance-sensitive paths.
func (k Public) B32() *[32]byte { return (*[32]byte)(&k) }

func (k Private) Public() Public {
	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, (*[32]byte)(&k))
	return Public(pub)
}

func (k Private) SharedSecret(pub Public) (ss [32]byte) {
	apk := (*[32]byte)(&pub)
	ask := (*[32]byte)(&k)
	curve25519.ScalarMult(&ss, ask, apk)
	return ss
}

// NewPublicFromHexMem parses a public key in its hex form, given in m.
// The provided m must be exactly 64 bytes in length.
func NewPublicFromHexMem(m mem.RO) (Public, error) {
	if m.Len() != 64 {
		return Public{}, errors.New("invalid length")
	}
	var p Public
	for i := range p {
		a, ok1 := fromHexChar(m.At(i*2 + 0))
		b, ok2 := fromHexChar(m.At(i*2 + 1))
		if !ok1 || !ok2 {
			return Public{}, errors.New("invalid hex character")
		}
		p[i] = (a << 4) | b
	}
	return p, nil
}
