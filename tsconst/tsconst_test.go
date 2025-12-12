// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconst

import "testing"

func TestDerpHostname(t *testing.T) {
	if DerpHostname == "" {
		t.Error("DerpHostname is empty")
	}
}
