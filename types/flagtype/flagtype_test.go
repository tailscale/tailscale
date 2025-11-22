// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package flagtype

import "testing"

func TestHTTPFlag(t *testing.T) {
	var f HTTPFlag
	if err := f.Set("http://example.com"); err != nil {
		t.Fatalf("Set() failed: %v", err)
	}
}
