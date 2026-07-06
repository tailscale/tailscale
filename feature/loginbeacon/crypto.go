// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// This package intentionally avoids [types/key/disco] and its NaCl-box
// wrapping: box.Precompute does HSalsa20 over the X25519 output, which is
// awkward to reproduce in client crypto libraries that only expose raw
// X25519 + HKDF (e.g. CryptoKit, libsodium's crypto_kx). Doing it here as
// raw X25519 → HKDF-SHA256 → ChaCha20-Poly1305 keeps other-language
// implementations byte-compatible.

var hkdfSalt = []byte("tsloginbeacon-v1")

type ephemeralKey struct {
	priv [32]byte
	pub  [32]byte
}

func newEphemeralKey() (ephemeralKey, error) {
	var k ephemeralKey
	if _, err := io.ReadFull(rand.Reader, k.priv[:]); err != nil {
		return k, fmt.Errorf("loginbeacon: reading random: %w", err)
	}
	pub, err := curve25519.X25519(k.priv[:], curve25519.Basepoint)
	if err != nil {
		return k, fmt.Errorf("loginbeacon: deriving X25519 public key: %w", err)
	}
	copy(k.pub[:], pub)
	return k, nil
}

func (k *ephemeralKey) zero() {
	for i := range k.priv {
		k.priv[i] = 0
	}
}

func deriveKey(priv [32]byte, peerPub [32]byte, rid requestID) ([]byte, error) {
	shared, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	// X25519 returns an error on low-order outputs, but be paranoid.
	var zero [32]byte
	if subtleEqual(shared, zero[:]) {
		return nil, errors.New("loginbeacon: x25519 produced zero shared secret")
	}
	r := hkdf.New(sha256.New, shared, hkdfSalt, rid[:])
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func sealURL(priv [32]byte, peerPub [32]byte, rid requestID, url string) (*sealedURLMsg, error) {
	key, err := deriveKey(priv, peerPub, rid)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce[:], []byte(url), rid[:])
	return &sealedURLMsg{
		RequestID:  rid,
		Nonce:      nonce,
		Ciphertext: ct,
	}, nil
}

// openURL is only exercised in tests; in production the approving node opens.
func openURL(priv [32]byte, peerPub [32]byte, m *sealedURLMsg) (string, error) {
	key, err := deriveKey(priv, peerPub, m.RequestID)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	pt, err := aead.Open(nil, m.Nonce[:], m.Ciphertext, m.RequestID[:])
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func hashDeviceID(id string) [16]byte {
	sum := sha256.Sum256([]byte(id))
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
