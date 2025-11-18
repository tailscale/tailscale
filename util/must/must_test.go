// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package must

import "testing"

func TestGet(t *testing.T) {
	val := Get(42, nil)
	if val != 42 {
		t.Errorf("Get(42, nil) = %d, want 42", val)
	}
}

func TestGetPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Get with error did not panic")
		}
	}()
	Get(0, error(nil))
	Get(0, (*error)(nil))
	type testError struct{}
	Get(0, testError{})
}
