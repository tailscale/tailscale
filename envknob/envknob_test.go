// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package envknob

import (
	"testing"
	"time"

	"tailscale.com/types/opt"
)

// TestSetenvUpdatesRegistered verifies that Setenv updates the value
// returned by every kind of Register function, as their docs promise.
func TestSetenvUpdatesRegistered(t *testing.T) {
	const (
		strKey  = "TS_TEST_ENVKNOB_SETENV_STR"
		boolKey = "TS_TEST_ENVKNOB_SETENV_BOOL"
		optKey  = "TS_TEST_ENVKNOB_SETENV_OPTBOOL"
		durKey  = "TS_TEST_ENVKNOB_SETENV_DURATION"
		intKey  = "TS_TEST_ENVKNOB_SETENV_INT"
	)
	str := RegisterString(strKey)
	b := RegisterBool(boolKey)
	ob := RegisterOptBool(optKey)
	dur := RegisterDuration(durKey)
	n := RegisterInt(intKey)

	SetenvForTest(t, strKey, "x")
	SetenvForTest(t, boolKey, "true")
	SetenvForTest(t, optKey, "true")
	SetenvForTest(t, durKey, "3s")
	SetenvForTest(t, intKey, "42")

	if got := str(); got != "x" {
		t.Errorf("RegisterString after Setenv = %q; want %q", got, "x")
	}
	if got := b(); !got {
		t.Errorf("RegisterBool after Setenv = %v; want true", got)
	}
	if got, ok := ob().Get(); !ok || !got {
		t.Errorf("RegisterOptBool after Setenv = %q; want %q", ob(), opt.Bool("true"))
	}
	if got := dur(); got != 3*time.Second {
		t.Errorf("RegisterDuration after Setenv = %v; want 3s", got)
	}
	if got := n(); got != 42 {
		t.Errorf("RegisterInt after Setenv = %v; want 42", got)
	}
}
