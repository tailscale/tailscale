// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package precompress

import "testing"

func TestPrecompress(t *testing.T) {
	data := []byte("test data")
	result := Precompress(data)
	if len(result) == 0 {
		t.Error("Precompress returned empty")
	}
}
