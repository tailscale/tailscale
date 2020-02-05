// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logtail

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
		return nil, fmt.Errorf("logtail.PrivateID.MarhsalText: i=%d", i)
	}
	return b, nil
}

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
	var emptyID PrivateID
	if id == emptyID {
		panic("invalid logtail.Public() on an empty private ID")
	}
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

func (id PublicID) MarshalText() ([]byte, error) {
	b := make([]byte, hex.EncodedLen(len(id)))
	if i := hex.Encode(b, id[:]); i != len(b) {
		return nil, fmt.Errorf("logtail.PublicID.MarhsalText: i=%d", i)
	}
	return b, nil
}

func (id *PublicID) UnmarshalText(s []byte) error {
	b, err := hex.DecodeString(string(s))
	if err != nil {
		return fmt.Errorf("logtail.PublicID.UnmarshalText: %v", err)
	}
	if len(b) != len(id) {
		return fmt.Errorf("logtail.PublicID.UnmarshalText: invalid hex length: %d", len(b))
	}
	copy(id[:], b)
	return nil
}

func (id PublicID) String() string {
	b, err := id.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(b)
}
