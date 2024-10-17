// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package internal contains miscellaneous functions and types
// that are internal to the syspolicy packages.
package internal

import (
	"bytes"

	"github.com/go-json-experiment/json/jsontext"
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

// EqualJSONForTest compares the JSON in j1 and j2 for semantic equality.
// It returns "", "", true if j1 and j2 are equal. Otherwise, it returns
// indented versions of j1 and j2 and false.
func EqualJSONForTest(tb TB, j1, j2 jsontext.Value) (s1, s2 string, equal bool) {
	tb.Helper()
	j1 = j1.Clone()
	j2 = j2.Clone()
	// Canonicalize JSON values for comparison.
	if err := j1.Canonicalize(); err != nil {
		tb.Error(err)
	}
	if err := j2.Canonicalize(); err != nil {
		tb.Error(err)
	}
	// Check and return true if the two values are structurally equal.
	if bytes.Equal(j1, j2) {
		return "", "", true
	}
	// Otherwise, format the values for display and return false.
	if err := j1.Indent("", "\t"); err != nil {
		tb.Fatal(err)
	}
	if err := j2.Indent("", "\t"); err != nil {
		tb.Fatal(err)
	}
	return j1.String(), j2.String(), false
}
