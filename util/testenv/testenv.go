// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package testenv provides utility functions for tests. It does not depend on
// the `testing` package to allow usage in non-test code.
package testenv

import (
	"flag"

	"tailscale.com/types/lazy"
)

var lazyInTest lazy.SyncValue[bool]

// InTest reports whether the current binary is a test binary.
func InTest() bool {
	return lazyInTest.Get(func() bool {
		return flag.Lookup("test.v") != nil
	})
}
