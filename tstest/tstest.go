// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tstest provides utilities for use in unit tests.
package tstest

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
)

// AssertNotParallel asserts that t has not been marked as parallel.
// It panics (via t.Setenv) if t.Parallel has already been called.
//
// Use this when a test modifies package-level globals or other shared
// state that would be unsafe to modify concurrently with other tests.
func AssertNotParallel(t testing.TB) {
	t.Helper()
	t.Setenv("ASSERT_NOT_PARALLEL_TEST", "1") // panics if t.Parallel was called
}

// Replace replaces the value of target with val.
// The old value is restored when the test ends.
//
// When target is a package-level variable, the caller should also call
// [AssertNotParallel] to ensure the test is not running in parallel with
// other tests that may access the same variable.
func Replace[T any](t testing.TB, target *T, val T) {
	t.Helper()
	if target == nil {
		t.Fatalf("Replace: nil pointer")
		panic("unreachable") // pacify staticcheck
	}
	old := *target
	t.Cleanup(func() {
		*target = old
	})

	*target = val
}

// WaitFor retries try for up to maxWait.
// It returns nil once try returns nil the first time.
// If maxWait passes without success, it returns try's last error.
func WaitFor(maxWait time.Duration, try func() error) error {
	bo := backoff.NewBackoff("wait-for", logger.Discard, maxWait/4)
	deadline := time.Now().Add(maxWait)
	var err error
	for time.Now().Before(deadline) {
		err = try()
		if err == nil {
			break
		}
		bo.BackOff(context.Background(), err)
	}
	return err
}

var serializeParallel = envknob.RegisterBool("TS_SERIAL_TESTS")

// Parallel calls t.Parallel, unless TS_SERIAL_TESTS is set true.
func Parallel(t *testing.T) {
	if !serializeParallel() {
		t.Parallel()
	}
}

// RequireRoot skips the test if the current user is not root.
func RequireRoot(tb testing.TB) {
	tb.Helper()
	if os.Getuid() != 0 {
		tb.Skip("skipping test; requires root")
	}
}

// SkipOnKernelVersions skips the test if the current
// kernel version is in the specified list.
func SkipOnKernelVersions(t testing.TB, issue string, versions ...string) {
	major, minor, patch := KernelVersion()
	if major == 0 && minor == 0 && patch == 0 {
		t.Logf("could not determine kernel version")
		return
	}

	current := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	for _, v := range versions {
		if v == current {
			t.Skipf("skipping on kernel version %q - see issue %s", current, issue)
		}
	}
}
