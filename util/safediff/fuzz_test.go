// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package safediff

import (
	"strings"
	"testing"
)

func FuzzDiff(f *testing.F) {
	f.Fuzz(func(t *testing.T, x, y string, maxSize int) {
		const maxInput = 1e3
		if len(x) > maxInput {
			x = x[:maxInput]
		}
		if len(y) > maxInput {
			y = y[:maxInput]
		}
		diff, _ := Lines(x, y, maxSize) // make sure this does not panic
		if strings.Count(diff, "\n") > 1 && maxSize >= 0 && len(diff) > maxSize {
			t.Fatal("maxSize exceeded")
		}
	})
}
