// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import "testing"

func TestMaybeUnUTF16(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"abc", "abc"},             // UTF-8
		{"a\x00b\x00c\x00", "abc"}, // UTF-16-LE
		{"\x00a\x00b\x00c", "abc"}, // UTF-16-BE
	}

	for _, test := range tests {
		got := string(maybeUnUTF16([]byte(test.in)))
		if got != test.want {
			t.Errorf("maybeUnUTF16(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}
