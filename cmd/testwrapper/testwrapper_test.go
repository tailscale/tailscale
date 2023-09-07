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
