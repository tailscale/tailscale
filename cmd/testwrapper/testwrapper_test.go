// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
)

var (
	buildPath string
	buildErr  error
	buildOnce sync.Once
)

func cmdTestwrapper(t *testing.T, args ...string) *exec.Cmd {
	buildOnce.Do(func() {
		buildPath, buildErr = buildTestWrapper()
	})
	if buildErr != nil {
		t.Fatalf("building testwrapper: %s", buildErr)
	}
	return exec.Command(buildPath, args...)
}

func buildTestWrapper() (string, error) {
	dir, err := os.MkdirTemp("", "testwrapper")
	if err != nil {
		return "", fmt.Errorf("making temp dir: %w", err)
	}
	_, err = exec.Command("go", "build", "-o", dir, ".").Output()
	if err != nil {
		return "", fmt.Errorf("go build: %w", err)
	}
	return filepath.Join(dir, "testwrapper"), nil
}

func TestRetry(t *testing.T) {
	t.Parallel()

	testfile := filepath.Join(t.TempDir(), "retry_test.go")
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

	out, err := cmdTestwrapper(t, "-v", testfile).CombinedOutput()
	if err != nil {
		t.Fatalf("go run . %s: %s with output:\n%s", testfile, err, out)
	}

	// Replace the unpredictable timestamp with "0.00s".
	out = regexp.MustCompile(`\t\d+\.\d\d\ds\t`).ReplaceAll(out, []byte("\t0.00s\t"))

	want := []byte("ok\t" + testfile + "\t0.00s\t[attempt=2]")
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
	t.Parallel()

	testfile := filepath.Join(t.TempDir(), "noretry_test.go")
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

	out, err := cmdTestwrapper(t, "-v", testfile).Output()
	if err == nil {
		t.Fatalf("go run . %s: expected error but it succeeded with output:\n%s", testfile, out)
	}
	if code, ok := errExitCode(err); ok && code != 1 {
		t.Fatalf("expected exit code 1 but got %d", code)
	}

	want := []byte("Not retrying flaky tests because non-flaky tests failed.")
	if !bytes.Contains(out, want) {
		t.Fatalf("wanted output containing %q but got:\n%s", want, out)
	}

	if flakeRuns := bytes.Count(out, []byte("=== RUN   TestFlakeRun")); flakeRuns != 1 {
		t.Fatalf("expected TestFlakeRun to be run once but was run %d times in output:\n%s", flakeRuns, out)
	}

	if testing.Verbose() {
		t.Logf("success - output:\n%s", out)
	}
}

func TestBuildError(t *testing.T) {
	t.Parallel()

	// Construct our broken package.
	testfile := filepath.Join(t.TempDir(), "builderror_test.go")
	code := []byte("package builderror_test\n\nderp")
	err := os.WriteFile(testfile, code, 0o644)
	if err != nil {
		t.Fatalf("writing package: %s", err)
	}

	buildErr := []byte("builderror_test.go:3:1: expected declaration, found derp\nFAIL	command-line-arguments [setup failed]")

	// Confirm `go test` exits with code 1.
	goOut, err := exec.Command("go", "test", testfile).CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("go test %s: expected error with exit code 0 but got: %v", testfile, err)
	}
	if !bytes.Contains(goOut, buildErr) {
		t.Fatalf("go test %s: expected build error containing %q but got:\n%s", testfile, buildErr, goOut)
	}

	// Confirm `testwrapper` exits with code 1.
	twOut, err := cmdTestwrapper(t, testfile).CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("testwrapper %s: expected error with exit code 0 but got: %v", testfile, err)
	}
	if !bytes.Contains(twOut, buildErr) {
		t.Fatalf("testwrapper %s: expected build error containing %q but got:\n%s", testfile, buildErr, twOut)
	}

	if testing.Verbose() {
		t.Logf("success - output:\n%s", twOut)
	}
}

func TestTimeout(t *testing.T) {
	t.Parallel()

	// Construct our broken package.
	testfile := filepath.Join(t.TempDir(), "timeout_test.go")
	code := []byte(`package noretry_test

import (
	"testing"
	"time"
)

func TestTimeout(t *testing.T) {
	time.Sleep(500 * time.Millisecond)
}
`)
	err := os.WriteFile(testfile, code, 0o644)
	if err != nil {
		t.Fatalf("writing package: %s", err)
	}

	out, err := cmdTestwrapper(t, testfile, "-timeout=20ms").CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("testwrapper %s: expected error with exit code 0 but got: %v; output was:\n%s", testfile, err, out)
	}
	if want := "panic: test timed out after 20ms"; !bytes.Contains(out, []byte(want)) {
		t.Fatalf("testwrapper %s: expected build error containing %q but got:\n%s", testfile, buildErr, out)
	}

	if testing.Verbose() {
		t.Logf("success - output:\n%s", out)
	}
}

func errExitCode(err error) (int, bool) {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), true
	}
	return 0, false
}
