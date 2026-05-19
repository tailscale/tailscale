// Copyright (c) Tailscale Inc & contributors
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
	"runtime"
	"strings"
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

// TestRaceSuppressesFlakyRetry verifies that detecting a data race
// in a package's output stops testwrapper from retrying any flaky
// test in that package. Races are too serious to paper over: the
// flaky test might not even be the one whose code is racy, and a
// retry without the racy goroutine could silently hide the bug.
func TestRaceSuppressesFlakyRetry(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("test requires the race detector, which needs linux/amd64")
	}
	t.Parallel()

	testfile := filepath.Join(t.TempDir(), "raceretry_test.go")
	code := []byte(`package raceretry_test

import (
	"sync"
	"testing"
	"tailscale.com/cmd/testwrapper/flakytest"
)

var counter int

func TestRace(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); counter++ }()
	go func() { defer wg.Done(); counter++ }()
	wg.Wait()
}

func TestFlaky(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/0")
	t.Fatal("flaky test failing; would normally be retried")
}
`)
	if err := os.WriteFile(testfile, code, 0o644); err != nil {
		t.Fatalf("writing package: %s", err)
	}

	out, err := cmdTestwrapper(t, testfile, "-race").CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("testwrapper %s -race: expected exit code 1, got %v; output was:\n%s", testfile, err, out)
	}
	if want := "WARNING: DATA RACE"; !bytes.Contains(out, []byte(want)) {
		t.Fatalf("expected race report in output, got:\n%s", out)
	}
	if want := "Not retrying flaky tests"; !bytes.Contains(out, []byte(want)) {
		t.Fatalf("expected no-retry message in output, got:\n%s", out)
	}
	if got := bytes.Count(out, []byte("Attempt #")); got != 0 {
		t.Fatalf("expected no retry attempts to be made, but %d were:\n%s", got, out)
	}
	if got := bytes.Count(out, []byte("=== RUN   TestFlaky")); got != 1 {
		t.Fatalf("expected TestFlaky to be run exactly once, ran %d times:\n%s", got, out)
	}

	if testing.Verbose() {
		t.Logf("success - output:\n%s", out)
	}
}

// TestRaceAttributedToPassingTest covers the case where go test
// attributes a data race report to a test that itself reports PASS
// (e.g. when the racing goroutines outlive the test that spawned
// them and TSan prints during a different test's window). Without
// the race-detection fix, the WARNING: DATA RACE block would be
// stuck in a passing test's log buffer and dropped on the floor.
// See https://github.com/tailscale/tailscale/issues/19603.
func TestRaceAttributedToPassingTest(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("test requires the race detector, which needs linux/amd64")
	}
	t.Parallel()

	testfile := filepath.Join(t.TempDir(), "race_test.go")
	code := []byte(`package race_test

import (
	"sync"
	"testing"
)

var counter int
var wg sync.WaitGroup

func TestSpawn(t *testing.T) {
	wg.Add(2)
	go func() { defer wg.Done(); counter++ }()
	go func() { defer wg.Done(); counter++ }()
}

func TestWait(t *testing.T) {
	wg.Wait()
}
`)
	if err := os.WriteFile(testfile, code, 0o644); err != nil {
		t.Fatalf("writing package: %s", err)
	}

	out, err := cmdTestwrapper(t, testfile, "-race").CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("testwrapper %s -race: expected exit code 1, got %v; output was:\n%s", testfile, err, out)
	}
	if want := "WARNING: DATA RACE"; !bytes.Contains(out, []byte(want)) {
		t.Fatalf("expected race report in output, got:\n%s", out)
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

	wantErr := "builderror_test.go:3:1: expected declaration, found derp\nFAIL"

	// Confirm `go test` exits with code 1.
	goOut, err := exec.Command("go", "test", testfile).CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("go test %s: got exit code %d, want 1 (err: %v)", testfile, code, err)
	}
	if !strings.Contains(string(goOut), wantErr) {
		t.Fatalf("go test %s: got output %q, want output containing %q", testfile, goOut, wantErr)
	}

	// Confirm `testwrapper` exits with code 1.
	twOut, err := cmdTestwrapper(t, testfile).CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("testwrapper %s: got exit code %d, want 1 (err: %v)", testfile, code, err)
	}
	if !strings.Contains(string(twOut), wantErr) {
		t.Fatalf("testwrapper %s: got output %q, want output containing %q", testfile, twOut, wantErr)
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

func TestCached(t *testing.T) {
	t.Parallel()

	// Construct our trivial package.
	pkgDir := t.TempDir()
	goVersion := runtime.Version()
	goVersion = strings.TrimPrefix(goVersion, "go")
	goVersion, _, _ = strings.Cut(goVersion, "-X:") // map 1.26.1-X:nogreenteagc to 1.26.1

	goMod := fmt.Sprintf(`module example.com

go %s
`, goVersion)
	test := `package main
import "testing"

func TestCached(t *testing.T) {}
`

	for f, c := range map[string]string{
		"go.mod":         goMod,
		"cached_test.go": test,
	} {
		err := os.WriteFile(filepath.Join(pkgDir, f), []byte(c), 0o644)
		if err != nil {
			t.Fatalf("writing package: %s", err)
		}
	}

	for name, args := range map[string][]string{
		"without_flags":     {"./..."},
		"with_short":        {"./...", "-short"},
		"with_coverprofile": {"./...", "-coverprofile=" + filepath.Join(t.TempDir(), "coverage.out")},
	} {
		t.Run(name, func(t *testing.T) {
			var (
				out []byte
				err error
			)
			for range 2 {
				cmd := cmdTestwrapper(t, args...)
				cmd.Dir = pkgDir
				out, err = cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("testwrapper ./...: expected no error but got: %v; output was:\n%s", err, out)
				}
			}

			want := []byte("ok\texample.com\t(cached)")
			if !bytes.Contains(out, want) {
				t.Fatalf("wanted output containing %q but got:\n%s", want, out)
			}

			if testing.Verbose() {
				t.Logf("success - output:\n%s", out)
			}
		})
	}
}

func errExitCode(err error) (int, bool) {
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exit.ExitCode(), true
	}
	return 0, false
}
