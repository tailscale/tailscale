// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// PrivateID represents an instance that write logs.
// Private IDs are only shared with the server when writing logs.
type PrivateID [32]byte

// Safely generate a new PrivateId for use in Config objects.
// You should persist this across runs of an instance of your app, so that
// it can append to the same log file on each run.
func NewPrivateID() (id PrivateID, err error) {
	_, err = rand.Read(id[:])
	if err != nil {
		return PrivateID{}, err
	}
	// Clamping, for future use.
	id[0] &= 248
	id[31] = (id[31] & 127) | 64
	return id, nil
}

func (id PrivateID) MarshalText() ([]byte, error) {
	b := make([]byte, hex.EncodedLen(len(id)))
	if i := hex.Encode(b, id[:]); i != len(b) {
		return nil, fmt.Errorf("logtail.PrivateID.MarshalText: i=%d", i)
	}
	return b, nil
}

// ParsePrivateID returns a PrivateID from its hex (String) representation.
func ParsePrivateID(s string) (PrivateID, error) {
	if len(s) != 64 {
		return PrivateID{}, errors.New("invalid length")
	}
	var p PrivateID
	for i := range p {
		a, ok1 := fromHexChar(s[i*2+0])
		b, ok2 := fromHexChar(s[i*2+1])
		if !ok1 || !ok2 {
			return PrivateID{}, errors.New("invalid hex character")
		}
		p[i] = (a << 4) | b
	}
	return p, nil
}

// IsZero reports whether id is the zero value.
func (id PrivateID) IsZero() bool { return id == PrivateID{} }

func (id *PrivateID) UnmarshalText(s []byte) error {
	b, err := hex.DecodeString(string(s))
	if err != nil {
		return fmt.Errorf("logtail.PrivateID.UnmarshalText: %v", err)
	}
	if len(b) != len(id) {
		return fmt.Errorf("logtail.PrivateID.UnmarshalText: invalid hex length: %d", len(b))
	}
	copy(id[:], b)
	return nil
}

func (id PrivateID) String() string {
	b, err := id.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(b)
}

func (id PrivateID) Public() (pub PublicID) {
	h := sha256.New()
	h.Write(id[:])
	if n := copy(pub[:], h.Sum(pub[:0])); n != len(pub) {
		panic(fmt.Sprintf("public id short copy: %d", n))
	}
	return pub
}

// PublicID represents an instance in the logs service for reading and adoption.
// The public ID value is a SHA-256 hash of a private ID.
type PublicID [sha256.Size]byte

// ParsePublicID returns a PublicID from its hex (String) representation.
func ParsePublicID(s string) (PublicID, error) {
	if len(s) != sha256.Size*2 {
		return PublicID{}, errors.New("invalid length")
	}
	var p PublicID
	for i := range p {
		a, ok1 := fromHexChar(s[i*2+0])
		b, ok2 := fromHexChar(s[i*2+1])
		if !ok1 || !ok2 {
			return PublicID{}, errors.New("invalid hex character")
		}
		p[i] = (a << 4) | b
	}
	return p, nil
}

// MustParsePublicID calls ParsePublicID and panics in case of an error.
// It is intended for use with constant strings, typically in tests.
func MustParsePublicID(s string) PublicID {
	id, err := ParsePublicID(s)
	if err != nil {
		panic(err)
	}
	return id
}

func (id PublicID) MarshalText() ([]byte, error) {
	b := make([]byte, hex.EncodedLen(len(id)))
	if i := hex.Encode(b, id[:]); i != len(b) {
		return nil, fmt.Errorf("logtail.PublicID.MarshalText: i=%d", i)
	}
	return b, nil
}

func (id *PublicID) UnmarshalText(s []byte) error {
	if len(s) != len(id)*2 {
		return fmt.Errorf("logtail.PublicID.UnmarshalText: invalid hex length: %d", len(s))
	}
	for i := range id {
		a, ok1 := fromHexChar(s[i*2+0])
		b, ok2 := fromHexChar(s[i*2+1])
		if !ok1 || !ok2 {
			return errors.New("invalid hex character")
		}
		id[i] = (a << 4) | b
	}
	return nil
}

func (id PublicID) String() string {
	b, err := id.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(b)
}

// fromHexChar converts a hex character into its value and a success flag.
func fromHexChar(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}

	return 0, false
}

func (id1 PublicID) Less(id2 PublicID) bool {
	for i, c1 := range id1[:] {
		c2 := id2[i]
		if c1 != c2 {
			return c1 < c2
		}
	}
	return false // equal
}

func (id PublicID) IsZero() bool {
	return id == PublicID{}
}

func (id PublicID) Prefix64() uint64 {
	return binary.BigEndian.Uint64(id[:8])
}
