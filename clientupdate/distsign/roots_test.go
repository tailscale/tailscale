// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package distsign

import "testing"

func TestParseRoots(t *testing.T) {
	roots, err := parseRoots()
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) == 0 {
		t.Error("parseRoots returned no root keys")
	}
}
