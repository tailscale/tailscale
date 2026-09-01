// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package nocasemaps

import (
	"strings"
	"testing"
)

func FuzzAppendToLower(f *testing.F) {
	for _, tt := range lowerTests {
		f.Add(tt.in)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got := string(appendToLower(nil, in))
		want := strings.ToLower(in)
		if got != want {
			t.Errorf("appendToLower(%q) = %q, want %q", in, got, want)
		}
	})
}
