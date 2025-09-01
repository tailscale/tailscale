// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ptype

import (
	"encoding"
	"testing"

	"tailscale.com/tstest/deptest"
)

var (
	_ encoding.TextMarshaler   = (*Visibility)(nil)
	_ encoding.TextUnmarshaler = (*Visibility)(nil)
)

func TestImports(t *testing.T) {
	deptest.DepChecker{
		OnDep: func(dep string) {
			t.Errorf("unexpected dep %q in leaf package; this package should not contain much code", dep)
		},
	}.Check(t)
}
