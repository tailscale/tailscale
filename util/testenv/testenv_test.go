// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package testenv

import (
	"reflect"
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		BadDeps: map[string]string{
			"testing": "see pkg docs",
		},
	}.Check(t)
}

func TestInParallelTestTrue(t *testing.T) {
	t.Parallel()
	if !InParallelTest(t) {
		t.Fatal("InParallelTest should return true once t.Parallel has been called")
	}
}

func TestInParallelTestFalse(t *testing.T) {
	if InParallelTest(t) {
		t.Fatal("InParallelTest should return false before t.Parallel has been called")
	}
}

// TestMatchesTestingTB verifies that TB has every exported method of
// testing.TB, with matching signatures. It can't be a compile-time
// assertion because testing.TB has an unexported method.
func TestMatchesTestingTB(t *testing.T) {
	want := reflect.TypeFor[testing.TB]()
	got := reflect.TypeFor[TB]()
	for m := range want.Methods() {
		if m.PkgPath != "" {
			continue // unexported
		}
		gm, ok := got.MethodByName(m.Name)
		if !ok {
			t.Errorf("TB lacks method %s%v", m.Name, m.Type)
			continue
		}
		if gm.Type != m.Type {
			t.Errorf("TB method %s has type %v; want %v", m.Name, gm.Type, m.Type)
		}
	}
}
