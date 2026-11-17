// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// multiPkgDir creates a temporary directory for test packages under
// testdata, so the packages are inside this module but ignored by
// "./..." patterns if a test ever leaks them.
func multiPkgDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("testdata", "multipkg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// writePkg writes a test-only package named name under dir with the
// given test source and returns its relative package pattern.
func writePkg(t *testing.T, dir, name, src string) string {
	t.Helper()
	pkgDir := filepath.Join(dir, name)
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, name+"_test.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return "./" + filepath.ToSlash(pkgDir)
}

// importPath returns the import path of a package written by writePkg.
func importPath(pattern string) string {
	return "tailscale.com/cmd/testwrapper/" + strings.TrimPrefix(pattern, "./")
}

// firstPassRuns returns the debug "running ..." lines for first-pass
// go test invocations, which unlike retries have no --run flag.
func firstPassRuns(out []byte) []string {
	var runs []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "running test") && !strings.Contains(line, "--run") {
			runs = append(runs, line)
		}
	}
	return runs
}

const passSrc = `package pass_test

import "testing"

func TestPass(t *testing.T) {}
`

const flakySrc = `package flaky_test

import (
	"os"
	"testing"
)

func TestFlaky(t *testing.T) {
	if os.Getenv("TS_TESTWRAPPER_ATTEMPT") == "1" {
		t.Fatal("failing on the first attempt so the wrapper retries")
	}
}
`

const failSrc = `package fail_test

import "testing"

func TestAlwaysFails(t *testing.T) { t.Fatal("nope") }
`

// TestMultiPackage covers several package patterns on one command line:
// the first pass must be a single go test invocation naming all of
// them, and results, flake retries, and permanent failures must still be
// attributed to the right package.
func TestMultiPackage(t *testing.T) {
	t.Parallel()

	dir := multiPkgDir(t)
	passPkg := writePkg(t, dir, "pass", passSrc)
	flakyPkg := writePkg(t, dir, "flaky", flakySrc)
	failPkg := writePkg(t, dir, "fail", failSrc)

	cmd := cmdTestwrapper(t, passPkg, flakyPkg, failPkg)
	cmd.Env = append(cmd.Env, "TS_TESTWRAPPER_DEBUG=1")
	out, err := cmd.CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("got exit code %d, want 1 (err: %v) with output:\n%s", code, err, out)
	}

	runs := firstPassRuns(out)
	if len(runs) != 1 {
		t.Errorf("got %d first-pass go test invocations, want 1:\n%s\noutput:\n%s", len(runs), strings.Join(runs, "\n"), out)
	} else {
		for _, p := range []string{passPkg, flakyPkg, failPkg} {
			if !strings.Contains(runs[0], " "+p+" ") {
				t.Errorf("first-pass invocation %q lacks package %q", runs[0], p)
			}
		}
	}

	for _, want := range []string{
		"ok\t" + importPath(passPkg),
		"FAIL\t" + importPath(flakyPkg), // first pass fails; the retry is per test
		"FAIL\t" + importPath(failPkg),
		"flakytest failures JSON:",
		"permanent test failures JSON:",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	flakyLine, permLine := jsonLines(out)
	if !strings.Contains(flakyLine, importPath(flakyPkg)) || !strings.Contains(flakyLine, "TestFlaky") {
		t.Errorf("flaky failures JSON %q should name %s TestFlaky", flakyLine, importPath(flakyPkg))
	}
	if !strings.Contains(permLine, importPath(failPkg)) || !strings.Contains(permLine, "TestAlwaysFails") {
		t.Errorf("permanent failures JSON %q should name %s TestAlwaysFails", permLine, importPath(failPkg))
	}
	if strings.Contains(permLine, "TestFlaky") || strings.Contains(flakyLine, "TestAlwaysFails") {
		t.Errorf("failures attributed to the wrong list:\nflaky: %s\npermanent: %s", flakyLine, permLine)
	}
}

// jsonLines returns the flakytest and permanent failures JSON lines
// from testwrapper output, or "" for each that is absent.
func jsonLines(out []byte) (flaky, permanent string) {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "flakytest failures JSON:") {
			flaky = line
		}
		if strings.HasPrefix(line, "permanent test failures JSON:") {
			permanent = line
		}
	}
	return flaky, permanent
}

// TestMultiPackageBuildError covers a build error in one package of a
// batch: the other packages still run and report, and the wrapper
// exits with go test's exit code.
func TestMultiPackageBuildError(t *testing.T) {
	t.Parallel()

	dir := multiPkgDir(t)
	passPkg := writePkg(t, dir, "pass", passSrc)
	brokenPkg := writePkg(t, dir, "broken", "package broken_test\n\nderp\n")

	out, err := cmdTestwrapper(t, passPkg, brokenPkg).CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("got exit code %d, want 1 (err: %v) with output:\n%s", code, err, out)
	}
	for _, want := range []string{
		"ok\t" + importPath(passPkg),
		"expected declaration, found derp",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// TestMultiFile covers several .go file arguments: each is its own
// "command-line-arguments" package, so each gets its own first-pass
// invocation and retries target the right file.
func TestMultiFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	fileA := filepath.Join(dir, "a_test.go")
	fileB := filepath.Join(dir, "b_test.go")
	if err := os.WriteFile(fileA, []byte(passSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileB, []byte(flakySrc), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := cmdTestwrapper(t, fileA, fileB)
	cmd.Env = append(cmd.Env, "TS_TESTWRAPPER_DEBUG=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("testwrapper: %v with output:\n%s", err, out)
	}
	if runs := firstPassRuns(out); len(runs) != 2 {
		t.Errorf("got %d first-pass go test invocations, want 2 (one per file):\n%s\noutput:\n%s", len(runs), strings.Join(runs, "\n"), out)
	}
	wantRetry := fileB + " --run ^(TestFlaky)$"
	if !bytes.Contains(out, []byte(wantRetry)) {
		t.Errorf("output lacks retry of %q:\n%s", wantRetry, out)
	}
	if bytes.Contains(out, []byte("permanent test failures JSON:")) {
		t.Errorf("unexpected permanent failures:\n%s", out)
	}
}
