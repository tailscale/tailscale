// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package key

import (
	"testing"
)

func TestTextUnmarshal(t *testing.T) {
	p := Public{1, 2}
	text, err := p.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var p2 Public
	if err := p2.UnmarshalText(text); err != nil {
		t.Fatal(err)
	}
	if p != p2 {
		t.Fatalf("mismatch; got %x want %x", p2, p)
	}
}
