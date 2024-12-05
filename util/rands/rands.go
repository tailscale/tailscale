// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package rands contains utility functions for randomness.
package rands

import (
	crand "crypto/rand"
	"encoding/hex"
)

// HexString returns a string of n cryptographically random lowercase
// hex characters.
//
// That is, HexString(3) returns something like "0fc", containing 12
// bits of randomness.
func HexString(n int) string {
	nb := n / 2
	if n%2 == 1 {
		nb++
	}
	b := make([]byte, nb)
	crand.Read(b)
	return hex.EncodeToString(b)[:n]
}
