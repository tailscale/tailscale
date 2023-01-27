// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tkatype

import (
	"testing"

	"golang.org/x/crypto/blake2s"
)

func TestSigHashSize(t *testing.T) {
	var sigHash AUMSigHash
	if len(sigHash) != blake2s.Size {
		t.Errorf("AUMSigHash is wrong size: got %d, want %d", len(sigHash), blake2s.Size)
	}

	var nksHash NKSSigHash
	if len(nksHash) != blake2s.Size {
		t.Errorf("NKSSigHash is wrong size: got %d, want %d", len(nksHash), blake2s.Size)
	}
}
