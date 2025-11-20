// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		BadDeps: map[string]string{
			"tailscale.com/tailcfg": "circular dependency via go generate",
			"tailscale.com/version": "circular dependency via go generate",
		},
	}.Check(t)
}
