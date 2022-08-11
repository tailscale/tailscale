// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tkatype

import (
	"golang.org/x/crypto/blake2s"
	"testing"
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
