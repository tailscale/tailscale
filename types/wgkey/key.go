// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wgkey contains types and helpers for WireGuard keys.
// It is very similar to package tailscale.com/types/key,
// which is also used for curve25519 keys.
// These keys are used for WireGuard clients;
// those keys are used in other curve25519 clients.
package wgkey

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// Size is the number of bytes in a curve25519 key.
const Size = 32

// A Key is a curve25519 key.
// It is used by WireGuard to represent public and preshared keys.
type Key [Size]byte

// NewPreshared generates a new random Key.
func NewPreshared() (*Key, error) {
	var k [Size]byte
	_, err := rand.Read(k[:])
	if err != nil {
		return nil, err
	}
	return (*Key)(&k), nil
}

func Parse(b64 string) (*Key, error) { return parseBase64(base64.StdEncoding, b64) }

func ParseHex(s string) (Key, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("invalid hex key (%q): %w", s, err)
	}
	if len(b) != Size {
		return Key{}, fmt.Errorf("invalid hex key (%q): length=%d, want %d", s, len(b), Size)
	}

	var key Key
	copy(key[:], b)
	return key, nil
}

func ParsePrivateHex(v string) (Private, error) {
	k, err := ParseHex(v)
	if err != nil {
		return Private{}, err
	}
	pk := Private(k)
	if pk.IsZero() {
		// Do not clamp a zero key, pass the zero through
		// (much like NaN propagation) so that IsZero reports
		// a useful result.
		return pk, nil
	}
	pk.clamp()
	return pk, nil
}

func (k Key) Base64() string    { return base64.StdEncoding.EncodeToString(k[:]) }
func (k Key) String() string    { return k.ShortString() }
func (k Key) HexString() string { return hex.EncodeToString(k[:]) }
func (k Key) Equal(k2 Key) bool { return subtle.ConstantTimeCompare(k[:], k2[:]) == 1 }

func (k *Key) ShortString() string {
	long := k.Base64()
	return "[" + long[0:5] + "]"
}

func (k *Key) IsZero() bool {
	if k == nil {
		return true
	}
	var zeros Key
	return subtle.ConstantTimeCompare(zeros[:], k[:]) == 1
}

func (k *Key) MarshalJSON() ([]byte, error) {
	if k == nil {
		return []byte("null"), nil
	}
	// TODO(josharian): use encoding/hex instead?
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, `"%x"`, k[:])
	return buf.Bytes(), nil
}

func (k *Key) UnmarshalJSON(b []byte) error {
	if k == nil {
		return errors.New("wgkey.Key: UnmarshalJSON on nil pointer")
	}
	if len(b) < 3 || b[0] != '"' || b[len(b)-1] != '"' {
		return errors.New("wgkey.Key: UnmarshalJSON not given a string")
	}
	b = b[1 : len(b)-1]
	key, err := ParseHex(string(b))
	if err != nil {
		return fmt.Errorf("wgkey.Key: UnmarshalJSON: %v", err)
	}
	copy(k[:], key[:])
	return nil
}

func (a *Key) LessThan(b *Key) bool {
	for i := range a {
		if a[i] < b[i] {
			return true
		} else if a[i] > b[i] {
			return false
		}
	}
	return false
}

// A Private is a curve25519 key.
// It is used by WireGuard to represent private keys.
type Private [Size]byte

// NewPrivate generates a new curve25519 secret key.
// It conforms to the format described on https://cr.yp.to/ecdh.html.
func NewPrivate() (Private, error) {
	k, err := NewPreshared()
	if err != nil {
		return Private{}, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return (Private)(*k), nil
}

func ParsePrivate(b64 string) (*Private, error) {
	k, err := parseBase64(base64.StdEncoding, b64)
	return (*Private)(k), err
}

func (k *Private) String() string        { return base64.StdEncoding.EncodeToString(k[:]) }
func (k *Private) HexString() string     { return hex.EncodeToString(k[:]) }
func (k *Private) Equal(k2 Private) bool { return subtle.ConstantTimeCompare(k[:], k2[:]) == 1 }

func (k *Private) IsZero() bool {
	pk := Key(*k)
	return pk.IsZero()
}

func (k *Private) clamp() {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

// Public computes the public key matching this curve25519 secret key.
func (k *Private) Public() Key {
	pk := Key(*k)
	if pk.IsZero() {
		panic("Tried to generate emptyPrivate.Public()")
	}
	var p [Size]byte
	curve25519.ScalarBaseMult(&p, (*[Size]byte)(k))
	return (Key)(p)
}

func (k Private) MarshalText() ([]byte, error) {
	// TODO(josharian): use encoding/hex instead?
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, `privkey:%x`, k[:])
	return buf.Bytes(), nil
}

func (k *Private) UnmarshalText(b []byte) error {
	s := string(b)
	if !strings.HasPrefix(s, `privkey:`) {
		return errors.New("wgkey.Private: UnmarshalText not given a private-key string")
	}
	s = strings.TrimPrefix(s, `privkey:`)
	key, err := ParseHex(s)
	if err != nil {
		return fmt.Errorf("wgkey.Private: UnmarshalText: %v", err)
	}
	copy(k[:], key[:])
	return nil
}

func parseBase64(enc *base64.Encoding, s string) (*Key, error) {
	k, err := enc.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid key (%q): %w", s, err)
	}
	if len(k) != Size {
		return nil, fmt.Errorf("invalid key (%q): length=%d, want %d", s, len(k), Size)
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func ParseSymmetric(b64 string) (Symmetric, error) {
	k, err := parseBase64(base64.StdEncoding, b64)
	if err != nil {
		return Symmetric{}, err
	}
	return Symmetric(*k), nil
}

func ParseSymmetricHex(s string) (Symmetric, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Symmetric{}, fmt.Errorf("invalid symmetric hex key (%q): %w", s, err)
	}
	if len(b) != chacha20poly1305.KeySize {
		return Symmetric{}, fmt.Errorf("invalid symmetric hex key length (%q): length=%d, want %d", s, len(b), chacha20poly1305.KeySize)
	}
	var key Symmetric
	copy(key[:], b)
	return key, nil
}

// Symmetric is a chacha20poly1305 key.
// It is used by WireGuard to represent pre-shared symmetric keys.
type Symmetric [chacha20poly1305.KeySize]byte

func (k Symmetric) Base64() string    { return base64.StdEncoding.EncodeToString(k[:]) }
func (k Symmetric) String() string    { return "sym:" + k.Base64()[:8] }
func (k Symmetric) HexString() string { return hex.EncodeToString(k[:]) }
func (k Symmetric) IsZero() bool      { return k.Equal(Symmetric{}) }
func (k Symmetric) Equal(k2 Symmetric) bool {
	return subtle.ConstantTimeCompare(k[:], k2[:]) == 1
}
