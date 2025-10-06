// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package flakytest

import (
	"os"
	"testing"
)

func TestIssueFormat(t *testing.T) {
	testCases := []struct {
		issue string
		want  bool
	}{
		{"https://github.com/tailscale/cOrp/issues/1234", true},
		{"https://github.com/otherproject/corp/issues/1234", true},
		{"https://not.huyb/tailscale/corp/issues/1234", false},
		{"https://github.com/tailscale/corp/issues/", false},
	}
	for _, testCase := range testCases {
		if issueRegexp.MatchString(testCase.issue) != testCase.want {
			ss := ""
			if !testCase.want {
				ss = " not"
			}
			t.Errorf("expected issueRegexp to%s match %q", ss, testCase.issue)
		}
	}
}

// TestFlakeRun is a test that fails when run in the testwrapper
// for the first time, but succeeds on the second run.
// It's used to test whether the testwrapper retries flaky tests.
func TestFlakeRun(t *testing.T) {
	Mark(t, "https://github.com/tailscale/tailscale/issues/0") // random issue
	e := os.Getenv(FlakeAttemptEnv)
	if e == "" {
		t.Skip("not running in testwrapper")
	}
	if e == "1" {
		t.Fatal("First run in testwrapper, failing so that test is retried. This is expected.")
	}
}

func TestMarked_Root(t *testing.T) {
	Mark(t, "https://github.com/tailscale/tailscale/issues/0")

	t.Run("child", func(t *testing.T) {
		t.Run("grandchild", func(t *testing.T) {
			if got, want := Marked(t), true; got != want {
				t.Fatalf("Marked(t) = %t, want %t", got, want)
			}
		})

		if got, want := Marked(t), true; got != want {
			t.Fatalf("Marked(t) = %t, want %t", got, want)
		}
	})

	if got, want := Marked(t), true; got != want {
		t.Fatalf("Marked(t) = %t, want %t", got, want)
	}
}

func TestMarked_Subtest(t *testing.T) {
	t.Run("flaky", func(t *testing.T) {
		Mark(t, "https://github.com/tailscale/tailscale/issues/0")

		t.Run("child", func(t *testing.T) {
			t.Run("grandchild", func(t *testing.T) {
				if got, want := Marked(t), true; got != want {
					t.Fatalf("Marked(t) = %t, want %t", got, want)
				}
			})

			if got, want := Marked(t), true; got != want {
				t.Fatalf("Marked(t) = %t, want %t", got, want)
			}
		})

		if got, want := Marked(t), true; got != want {
			t.Fatalf("Marked(t) = %t, want %t", got, want)
		}
	})

	if got, want := Marked(t), false; got != want {
		t.Fatalf("Marked(t) = %t, want %t", got, want)
	}
}
