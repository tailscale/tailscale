// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package testenv provides utility functions for tests. It does not depend on
// the `testing` package to allow usage in non-test code.
package testenv

import (
	"context"
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

// TB is testing.TB, to avoid importing "testing" in non-test code.
type TB interface {
	Cleanup(func())
	Error(args ...any)
	Errorf(format string, args ...any)
	Fail()
	FailNow()
	Failed() bool
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Helper()
	Log(args ...any)
	Logf(format string, args ...any)
	Name() string
	Setenv(key, value string)
	Chdir(dir string)
	Skip(args ...any)
	SkipNow()
	Skipf(format string, args ...any)
	Skipped() bool
	TempDir() string
	Context() context.Context
}

// InParallelTest reports whether t is running as a parallel test.
//
// Use of this function taints t such that its Parallel method (assuming t is an
// actual *testing.T) will panic if called after this function.
func InParallelTest(t TB) (isParallel bool) {
	defer func() {
		if r := recover(); r != nil {
			isParallel = true
		}
	}()
	t.Chdir(".") // panics in a t.Parallel test
	return false
}

// AssertInTest panics if called outside of a test binary.
func AssertInTest() {
	if !InTest() {
		panic("func called outside of test binary")
	}
}
