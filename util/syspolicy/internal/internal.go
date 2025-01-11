// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package internal contains miscellaneous functions and types
// that are internal to the syspolicy packages.
package internal

import (
	"tailscale.com/types/lazy"
	"tailscale.com/version"
)

// Init facilitates deferred invocation of initializers.
var Init lazy.DeferredInit

// OSForTesting is the operating system override used for testing.
// It follows the same naming convention as [version.OS].
var OSForTesting lazy.SyncValue[string]

// OS is like [version.OS], but supports a test hook.
func OS() string {
	return OSForTesting.Get(version.OS)
}

// TB is a subset of testing.TB that we use to set up test helpers.
// It's defined here to avoid pulling in the testing package.
type TB interface {
	Helper()
	Cleanup(func())
	Logf(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}
