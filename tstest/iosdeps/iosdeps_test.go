// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package iosdeps

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestDeps(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "ios",
		GOARCH: "arm64",
		BadDeps: map[string]string{
			"testing":       "do not use testing package in production code",
			"text/template": "linker bloat (MethodByName)",
			"html/template": "linker bloat (MethodByName)",
		},
	}.Check(t)
}
