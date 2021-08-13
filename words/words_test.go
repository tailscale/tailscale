// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package words

import (
	"strings"
	"testing"
)

func TestWords(t *testing.T) {
	test := func(t *testing.T, words []string) {
		t.Helper()
		if len(words) == 0 {
			t.Error("no words")
		}
		seen := map[string]bool{}
		for _, w := range words {
			if seen[w] {
				t.Errorf("dup word %q", w)
			}
			seen[w] = true
			if w == "" || strings.IndexFunc(w, nonASCIILower) != -1 {
				t.Errorf("malformed word %q", w)
			}
		}
	}
	t.Run("tails", func(t *testing.T) { test(t, Tails()) })
	t.Run("scales", func(t *testing.T) { test(t, Scales()) })
	t.Logf("%v tails * %v scales = %v beautiful combinations", len(Tails()), len(Scales()), len(Tails())*len(Scales()))
}

func nonASCIILower(r rune) bool {
	if 'a' <= r && r <= 'z' {
		return false
	}
	return true
}
