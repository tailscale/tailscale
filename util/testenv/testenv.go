// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package testenv provides utility functions for tests. It does not depend on
// the `testing` package to allow usage in non-test code.
package testenv

// InTest reports whether the current binary is a test binary.
func InTest() bool {
	return false
}
