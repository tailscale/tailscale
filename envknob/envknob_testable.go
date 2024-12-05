// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_not_in_tests

package envknob

import "runtime"

// GOOS reports the effective runtime.GOOS to run as.
//
// In practice this returns just runtime.GOOS, unless overridden by
// test TS_DEBUG_FAKE_GOOS.
//
// This allows changing OS-specific stuff like the IPN server behavior
// for tests so we can e.g. test Windows-specific behaviors on Linux.
// This isn't universally used.
func GOOS() string {
	if v := String("TS_DEBUG_FAKE_GOOS"); v != "" {
		return v
	}
	return runtime.GOOS
}
