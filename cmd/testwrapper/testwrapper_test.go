// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRetry(t *testing.T) {
	dir := t.TempDir()

	testfile := filepath.Join(dir, "retry_test.go")
	code := []byte(`package retry_test

import (
	"os"
	"testing"
	"tailscale.com/cmd/testwrapper/flakytest"
)

func TestOK(t *testing.T) {}

func TestFlakeRun(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/0") // random issue
	e := os.Getenv(flakytest.FlakeAttemptEnv)
	if e == "" {
		t.Skip("not running in testwrapper")
	}
	if e == "1" {
		t.Fatal("First run in testwrapper, failing so that test is retried. This is expected.")
	}
}
`)
	if err := os.WriteFile(testfile, code, 0o644); err != nil {
		t.Fatalf("writing package: %s", err)
	}

	out, err := exec.Command("go", "run", ".", "-v", testfile).CombinedOutput()
	if err != nil {
		t.Fatalf("go run . %s: %s with output:\n%s", testfile, err, out)
	}

	want := []byte("ok\t" + testfile + " [attempt=2]")
	if !bytes.Contains(out, want) {
		t.Fatalf("wanted output containing %q but got:\n%s", want, out)
	}

	if okRuns := bytes.Count(out, []byte("=== RUN   TestOK")); okRuns != 1 {
		t.Fatalf("expected TestOK to be run once but was run %d times in output:\n%s", okRuns, out)
	}
	if flakeRuns := bytes.Count(out, []byte("=== RUN   TestFlakeRun")); flakeRuns != 2 {
		t.Fatalf("expected TestFlakeRun to be run twice but was run %d times in output:\n%s", flakeRuns, out)
	}

	if testing.Verbose() {
		t.Logf("success - output:\n%s", out)
	}
}

func TestNoRetry(t *testing.T) {
	dir := t.TempDir()

	testfile := filepath.Join(dir, "noretry_test.go")
	code := []byte(`package noretry_test

import (
	"testing"
	"tailscale.com/cmd/testwrapper/flakytest"
)

func TestFlakeRun(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/0") // random issue
	t.Error("shouldn't be retried")
}

func TestAlwaysError(t *testing.T) {
	t.Error("error")
}
`)
	if err := os.WriteFile(testfile, code, 0o644); err != nil {
		t.Fatalf("writing package: %s", err)
	}

	out, err := exec.Command("go", "run", ".", testfile).Output()
	if err == nil {
		t.Fatalf("go run . %s: expected error but it succeeded with output:\n%s", testfile, out)
	}
	if code, _, ok := errExitCode(err); ok && code != 1 {
		t.Fatalf("expected exit code 1 but got %d", code)
	}

	want := []byte("Not retrying flaky tests because non-flaky tests failed.")
	if !bytes.Contains(out, want) {
		t.Fatalf("wanted output containing %q but got:\n%s", want, out)
	}
	if testing.Verbose() {
		t.Logf("success - output:\n%s", out)
	}
}

func TestBuildError(t *testing.T) {
	dir := t.TempDir()

	// Construct our broken package.
	testfile := filepath.Join(dir, "builderror_test.go")
	code := []byte("package builderror_test\n\nderp")
	err := os.WriteFile(testfile, code, 0o644)
	if err != nil {
		t.Fatalf("writing package: %s", err)
	}

	buildErr := []byte(`builderror_test.go:3:1: expected declaration, found derp`)

	// Confirm `go test` exits with code 1.
	_, err = exec.Command("go", "test", testfile).Output()
	if code, stderr, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("go test %s: expected error with exit code 0 but got: %v", testfile, err)
	} else if !bytes.Contains(stderr, buildErr) {
		t.Fatalf("go test %s: expected build error containing %q but got:\n%s", testfile, buildErr, stderr)
	}

	// Confirm `testwrapper` exits with code 1.
	_, err = exec.Command("go", "run", ".", testfile).Output()
	if code, stderr, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("testwrapper %s: expected error with exit code 0 but got: %v", testfile, err)
	} else if !bytes.Contains(stderr, buildErr) {
		t.Fatalf("testwrapper %s: expected build error containing %q but got:\n%s", testfile, buildErr, stderr)
	}
}

func errExitCode(err error) (int, []byte, bool) {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), exit.Stderr, true
	}
	return 0, nil, false
}
