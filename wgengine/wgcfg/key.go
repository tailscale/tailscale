// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgcfg

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

const KeySize = 32

// Key is curve25519 key.
// It is used by WireGuard to represent public and preshared keys.
type Key [KeySize]byte

// NewPresharedKey generates a new random key.
func NewPresharedKey() (*Key, error) {
	var k [KeySize]byte
	_, err := rand.Read(k[:])
	if err != nil {
		return nil, err
	}
	return (*Key)(&k), nil
}

func ParseKey(b64 string) (*Key, error) { return parseKeyBase64(base64.StdEncoding, b64) }

func ParseHexKey(s string) (Key, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Key{}, &ParseError{"invalid hex key: " + err.Error(), s}
	}
	if len(b) != KeySize {
		return Key{}, &ParseError{fmt.Sprintf("invalid hex key length: %d", len(b)), s}
	}

	var key Key
	copy(key[:], b)
	return key, nil
}

func ParsePrivateHexKey(v string) (PrivateKey, error) {
	k, err := ParseHexKey(v)
	if err != nil {
		return PrivateKey{}, err
	}
	pk := PrivateKey(k)
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
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, `"%x"`, k[:])
	return buf.Bytes(), nil
}

func (k *Key) UnmarshalJSON(b []byte) error {
	if k == nil {
		return errors.New("wgcfg.Key: UnmarshalJSON on nil pointer")
	}
	if len(b) < 3 || b[0] != '"' || b[len(b)-1] != '"' {
		return errors.New("wgcfg.Key: UnmarshalJSON not given a string")
	}
	b = b[1 : len(b)-1]
	key, err := ParseHexKey(string(b))
	if err != nil {
		return fmt.Errorf("wgcfg.Key: UnmarshalJSON: %v", err)
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

// PrivateKey is curve25519 key.
// It is used by WireGuard to represent private keys.
type PrivateKey [KeySize]byte

// NewPrivateKey generates a new curve25519 secret key.
// It conforms to the format described on https://cr.yp.to/ecdh.html.
func NewPrivateKey() (PrivateKey, error) {
	k, err := NewPresharedKey()
	if err != nil {
		return PrivateKey{}, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return (PrivateKey)(*k), nil
}

func ParsePrivateKey(b64 string) (*PrivateKey, error) {
	k, err := parseKeyBase64(base64.StdEncoding, b64)
	return (*PrivateKey)(k), err
}

func (k *PrivateKey) String() string           { return base64.StdEncoding.EncodeToString(k[:]) }
func (k *PrivateKey) HexString() string        { return hex.EncodeToString(k[:]) }
func (k *PrivateKey) Equal(k2 PrivateKey) bool { return subtle.ConstantTimeCompare(k[:], k2[:]) == 1 }

func (k *PrivateKey) IsZero() bool {
	pk := Key(*k)
	return pk.IsZero()
}

func (k *PrivateKey) clamp() {
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
}

// Public computes the public key matching this curve25519 secret key.
func (k *PrivateKey) Public() Key {
	pk := Key(*k)
	if pk.IsZero() {
		panic("Tried to generate emptyPrivateKey.Public()")
	}
	var p [KeySize]byte
	curve25519.ScalarBaseMult(&p, (*[KeySize]byte)(k))
	return (Key)(p)
}

func (k PrivateKey) MarshalText() ([]byte, error) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, `privkey:%x`, k[:])
	return buf.Bytes(), nil
}

func (k *PrivateKey) UnmarshalText(b []byte) error {
	s := string(b)
	if !strings.HasPrefix(s, `privkey:`) {
		return errors.New("wgcfg.PrivateKey: UnmarshalText not given a private-key string")
	}
	s = strings.TrimPrefix(s, `privkey:`)
	key, err := ParseHexKey(s)
	if err != nil {
		return fmt.Errorf("wgcfg.PrivateKey: UnmarshalText: %v", err)
	}
	copy(k[:], key[:])
	return nil
}

func (k PrivateKey) SharedSecret(pub Key) (ss [KeySize]byte) {
	apk := (*[KeySize]byte)(&pub)
	ask := (*[KeySize]byte)(&k)
	curve25519.ScalarMult(&ss, ask, apk) //lint:ignore SA1019 Jason says this is OK; match wireguard-go exactyl
	return ss
}

func parseKeyBase64(enc *base64.Encoding, s string) (*Key, error) {
	k, err := enc.DecodeString(s)
	if err != nil {
		return nil, &ParseError{"Invalid key: " + err.Error(), s}
	}
	if len(k) != KeySize {
		return nil, &ParseError{"Keys must decode to exactly 32 bytes", s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func ParseSymmetricKey(b64 string) (SymmetricKey, error) {
	k, err := parseKeyBase64(base64.StdEncoding, b64)
	if err != nil {
		return SymmetricKey{}, err
	}
	return SymmetricKey(*k), nil
}

func ParseSymmetricHexKey(s string) (SymmetricKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return SymmetricKey{}, &ParseError{"invalid symmetric hex key: " + err.Error(), s}
	}
	if len(b) != chacha20poly1305.KeySize {
		return SymmetricKey{}, &ParseError{fmt.Sprintf("invalid symmetric hex key length: %d", len(b)), s}
	}
	var key SymmetricKey
	copy(key[:], b)
	return key, nil
}

// SymmetricKey is a chacha20poly1305 key.
// It is used by WireGuard to represent pre-shared symmetric keys.
type SymmetricKey [chacha20poly1305.KeySize]byte

func (k SymmetricKey) Base64() string    { return base64.StdEncoding.EncodeToString(k[:]) }
func (k SymmetricKey) String() string    { return "sym:" + k.Base64()[:8] }
func (k SymmetricKey) HexString() string { return hex.EncodeToString(k[:]) }
func (k SymmetricKey) IsZero() bool      { return k.Equal(SymmetricKey{}) }
func (k SymmetricKey) Equal(k2 SymmetricKey) bool {
	return subtle.ConstantTimeCompare(k[:], k2[:]) == 1
}
