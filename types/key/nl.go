// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package key

import (
	"crypto/ed25519"

	"go4.org/mem"
	"tailscale.com/tka"
	"tailscale.com/types/structs"
)

const (
	// nlPrivateHexPrefix is the prefix used to identify a
	// hex-encoded network-lock key.
	nlPrivateHexPrefix = "nlpriv:"
)

// NLPrivate is a node-managed network-lock key, used for signing
// node-key signatures and authority update messages.
type NLPrivate struct {
	_ structs.Incomparable // because == isn't constant-time
	k [ed25519.PrivateKeySize]byte
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

// MarshalText implements encoding.TextMarshaler.
func (k NLPrivate) MarshalText() ([]byte, error) {
	return toHex(k.k[:], nlPrivateHexPrefix), nil
}

// Public returns the public component of this key.
func (k NLPrivate) Public() ed25519.PublicKey {
	return ed25519.PrivateKey(k.k[:]).Public().(ed25519.PublicKey)
}

// KeyID returns an identifier for this key.
func (k NLPrivate) KeyID() tka.KeyID {
	return tka.Key{
		Kind:   tka.Key25519,
		Public: k.Public(),
	}.ID()
}

// SignAUM implements tka.UpdateSigner.
func (k NLPrivate) SignAUM(a *tka.AUM) error {
	sigHash := a.SigHash()

	a.Signatures = append(a.Signatures, tka.Signature{
		KeyID:     k.KeyID(),
		Signature: ed25519.Sign(k.k[:], sigHash[:]),
	})
	return nil
}
