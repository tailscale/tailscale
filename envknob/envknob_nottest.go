// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_not_in_tests

package envknob

import "runtime"

func GOOS() string {
	// When the "ts_not_in_tests" build tag is used, we define this func to just
	// return a simple constant so callers optimize just as if the knob were not
	// present. We can then build production/optimized builds with the
	// "ts_not_in_tests" build tag.
	return runtime.GOOS
}
