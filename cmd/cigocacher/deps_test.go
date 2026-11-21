// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"strings"
	"testing"

	"tailscale.com/tstest/deptest"
)

// TestDeps checks that cigocacher depends on no other tailscale.com
// packages. The .github/actions/go-cache action caches the cigocacher
// binary keyed on only cmd/cigocacher, go.mod, and go.sum.
func TestDeps(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		deptest.DepChecker{
			GOOS:   goos,
			GOARCH: "amd64",
			OnDep: func(dep string) {
				if strings.HasPrefix(dep, "tailscale.com/") {
					t.Errorf("GOOS=%s: unexpected dependency %q; update the cache key in .github/actions/go-cache/action.yml", goos, dep)
				}
			},
		}.Check(t)
	}
}
