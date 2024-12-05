// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package jsonutil

// Bytes is a byte slice in a json-encoded struct.
// encoding/json assumes that []byte fields are hex-encoded.
// Bytes are not hex-encoded; they are treated the same as strings.
// This can avoid unnecessary allocations due to a round trip through strings.
type Bytes []byte

func (b *Bytes) UnmarshalText(text []byte) error {
	// Copy the contexts of text.
	*b = append(*b, text...)
	return nil
}
