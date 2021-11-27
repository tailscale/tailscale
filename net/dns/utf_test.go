// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
