// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package omit

import "testing"

func TestErr(t *testing.T) {
	if Err == nil {
		t.Error("omit.Err is nil")
	}
}
