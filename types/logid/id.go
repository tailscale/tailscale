// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package logid contains ID types for interacting with the log service.
package logid

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"unicode/utf8"
)

// PrivateID represents a log steam for writing.
// Private IDs are only shared with the server when writing logs.
type PrivateID [32]byte

// NewPrivateID generates a new random PrivateID.
// This should persist across runs of an instance of the application,
// so that it can append to the same log stream for each invocation.
func NewPrivateID() (id PrivateID, err error) {
	if _, err := rand.Read(id[:]); err != nil {
		return PrivateID{}, err
	}
	// Clamping, for future use.
	id[0] &= 248
	id[31] = (id[31] & 127) | 64
	return id, nil
}

// ParsePrivateID returns a PrivateID from its hex representation.
func ParsePrivateID(in string) (out PrivateID, err error) {
	err = parseID("logid.ParsePublicID", (*[32]byte)(&out), in)
	return out, err
}

func (id PrivateID) AppendText(b []byte) ([]byte, error) {
	return hex.AppendEncode(b, id[:]), nil
}

func (id PrivateID) MarshalText() ([]byte, error) {
	return id.AppendText(nil)
}

func (id *PrivateID) UnmarshalText(in []byte) error {
	return parseID("logid.PrivateID", (*[32]byte)(id), in)
}

func (id PrivateID) String() string {
	return string(hex.AppendEncode(nil, id[:]))
}

func (id PrivateID) IsZero() bool {
	return id == PrivateID{}
}

// Public returns the public ID of the private ID,
// which is the SHA-256 hash of the private ID.
func (id PrivateID) Public() (pub PublicID) {
	return PublicID(sha256.Sum256(id[:]))
}

// PublicID represents a log stream for reading.
// The PrivateID cannot be feasibly reversed from the PublicID.
type PublicID [sha256.Size]byte

// ParsePublicID returns a PublicID from its hex representation.
func ParsePublicID(in string) (out PublicID, err error) {
	err = parseID("logid.ParsePublicID", (*[32]byte)(&out), in)
	return out, err
}

func (id PublicID) AppendText(b []byte) ([]byte, error) {
	return hex.AppendEncode(b, id[:]), nil
}

func (id PublicID) MarshalText() ([]byte, error) {
	return id.AppendText(nil)
}

func (id *PublicID) UnmarshalText(in []byte) error {
	return parseID("logid.ParsePublicID", (*[32]byte)(id), in)
}

func (id PublicID) String() string {
	return string(hex.AppendEncode(nil, id[:]))
}

func (id1 PublicID) Less(id2 PublicID) bool {
	return id1.Compare(id2) < 0
}

func (id1 PublicID) Compare(id2 PublicID) int {
	return slices.Compare(id1[:], id2[:])
}

func (id PublicID) IsZero() bool {
	return id == PublicID{}
}

func (id PublicID) Prefix64() uint64 {
	return binary.BigEndian.Uint64(id[:8])
}

func parseID[Bytes []byte | string](funcName string, out *[32]byte, in Bytes) (err error) {
	if len(in) != 2*len(out) {
		return fmt.Errorf("%s: invalid hex length: %d", funcName, len(in))
	}
	var hexArr [2 * len(out)]byte
	copy(hexArr[:], in)
	if _, err := hex.Decode(out[:], hexArr[:]); err != nil {
		r, _ := utf8.DecodeRune(bytes.TrimLeft([]byte(in), "0123456789abcdefABCDEF"))
		return fmt.Errorf("%s: invalid hex character: %c", funcName, r)
	}
	return nil
}
