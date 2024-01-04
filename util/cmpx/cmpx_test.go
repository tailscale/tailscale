// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cmpx

import "testing"

func TestOr(t *testing.T) {
	if g, w := Or[string](), ""; g != w {
		t.Errorf("got %v; want %v", g, w)
	}
	if g, w := Or[int](), 0; g != w {
		t.Errorf("got %v; want %v", g, w)
	}
	if g, w := Or("", "foo", "bar"), "foo"; g != w {
		t.Errorf("got %v; want %v", g, w)
	}
	if g, w := Or("foo", "bar"), "foo"; g != w {
		t.Errorf("got %v; want %v", g, w)
	}
	if g, w := Or("", "", "bar"), "bar"; g != w {
		t.Errorf("got %v; want %v", g, w)
	}
}
