// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package envknob

import "testing"

func TestSetenvRegisterInt(t *testing.T) {
	const envVar = "TS_ENVKNOB_TEST_REGISTER_INT"
	get := RegisterInt(envVar)
	if got := get(); got != 0 {
		t.Fatalf("initial value = %d; want 0", got)
	}
	SetenvForTest(t, envVar, "42")
	if got := get(); got != 42 {
		t.Errorf("value after Setenv = %d; want 42", got)
	}
}
