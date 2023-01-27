// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package flakytest contains test helpers for marking a test as flaky. For
// tests run using cmd/testwrapper, a failed flaky test will cause tests to be
// re-run a few time until they succeed or exceed our iteration limit.
package flakytest

import (
	"os"
	"regexp"
	"testing"
)

// InTestWrapper returns whether or not this binary is running under our test
// wrapper.
func InTestWrapper() bool {
	return os.Getenv("TS_IN_TESTWRAPPER") != ""
}

var issueRegexp = regexp.MustCompile(`\Ahttps://github\.com/tailscale/[a-zA-Z0-9_.-]+/issues/\d+\z`)

// Mark sets the current test as a flaky test, such that if it fails, it will
// be retried a few times on failure. issue must be a GitHub issue that tracks
// the status of the flaky test being marked, of the format:
//
//	https://github.com/tailscale/myRepo-H3re/issues/12345
func Mark(t testing.TB, issue string) {
	if !issueRegexp.MatchString(issue) {
		t.Fatalf("bad issue format: %q", issue)
	}

	if !InTestWrapper() {
		return
	}

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("flakytest: signaling test wrapper to retry test")

			// Signal to test wrapper that we should restart.
			os.Exit(123)
		}
	})
}
