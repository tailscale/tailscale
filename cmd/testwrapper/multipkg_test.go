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

// hangSrc is a package that times out on the first attempt only. When the
// timeout occurs, TestFails has failed, TestParallel is paused, TestHang
// runs, and TestNotStarted has not started.
const hangSrc = `package hang_test

import (
	"os"
	"testing"
	"time"
)

func TestParallel(t *testing.T) { t.Parallel() }

func TestFails(t *testing.T) {
	if os.Getenv("TS_TESTWRAPPER_ATTEMPT") == "1" {
		t.Fatal("failing on the first attempt only")
	}
}

func TestHang(t *testing.T) {
	if os.Getenv("TS_TESTWRAPPER_ATTEMPT") == "1" {
		time.Sleep(time.Hour)
	}
}

func TestNotStarted(t *testing.T) {}
`

// TestPackageTimeoutNotRetried covers a package that times out: the wrapper
// must exit non-zero and must not retry any of its tests, or report them as
// flaky, because the tests that did not start never ran. Tests in other
// packages are still retried.
func TestPackageTimeoutNotRetried(t *testing.T) {
	t.Parallel()

	dir := multiPkgDir(t)
	hangPkg := writePkg(t, dir, "hang", hangSrc)
	flakyPkg := writePkg(t, dir, "flaky", flakySrc)

	out, err := cmdTestwrapper(t, hangPkg, flakyPkg, "-timeout=5s").CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("got exit code %d, want 1 (err: %v) with output:\n%s", code, err, out)
	}
	for _, want := range []string{
		"panic: test timed out after 5s",
		"testwrapper: " + importPath(hangPkg) + " did not complete; not retrying its tests (unfinished: TestHang TestParallel)\n",
		"[retry 1] " + importPath(flakyPkg) + ".TestFlaky: PASS",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if bytes.Contains(out, []byte("[retry 1] "+importPath(hangPkg))) {
		t.Errorf("tests of the package that did not complete were retried:\n%s", out)
	}
	flakyLine, permLine := jsonLines(out)
	if strings.Contains(flakyLine, importPath(hangPkg)) || strings.Contains(permLine, importPath(hangPkg)) {
		t.Errorf("tests of the package that did not complete are in the failures JSON:\nflaky: %s\npermanent: %s", flakyLine, permLine)
	}
	if !strings.Contains(flakyLine, "TestFlaky") {
		t.Errorf("flaky failures JSON %q should name TestFlaky", flakyLine)
	}
}

// TestPackagePanicNotRetried covers a package that a panic stops. The
// wrapper must exit non-zero and must not retry the tests of the package,
// because some of its tests did not start.
func TestPackagePanicNotRetried(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			// The panicking test and the paused parallel test have no result.
			name: "background-goroutine",
			src: `package bgpanic_test

import (
	"os"
	"testing"
)

func TestParallel(t *testing.T) { t.Parallel() }

func TestPanic(t *testing.T) {
	if os.Getenv("TS_TESTWRAPPER_ATTEMPT") == "1" {
		go func() { panic("background goroutine panic") }()
		select {}
	}
}
`,
			want: "did not complete; not retrying its tests (unfinished: TestPanic TestParallel)\n",
		},
		{
			// The testing package reports the panicking test as failed. No
			// other test is in progress, but TestNotStarted never runs.
			name: "test-goroutine",
			src: `package testpanic_test

import (
	"os"
	"testing"
)

func TestPanic(t *testing.T) {
	if os.Getenv("TS_TESTWRAPPER_ATTEMPT") == "1" {
		panic("test goroutine panic")
	}
}

func TestNotStarted(t *testing.T) {}
`,
			want: "did not complete; not retrying its tests\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkg := writePkg(t, multiPkgDir(t), "panicpkg", tt.src)
			out, err := cmdTestwrapper(t, pkg).CombinedOutput()
			if code, ok := errExitCode(err); !ok || code != 1 {
				t.Fatalf("got exit code %d, want 1 (err: %v) with output:\n%s", code, err, out)
			}
			if !bytes.Contains(out, []byte(tt.want)) {
				t.Errorf("output lacks %q:\n%s", tt.want, out)
			}
			if bytes.Contains(out, []byte("[retry ")) {
				t.Errorf("tests of the package that did not complete were retried:\n%s", out)
			}
		})
	}
}

// TestPackageTimeoutResultsSummary covers the results summary when the only
// failure is a package that times out: the summary must be written, and
// must show the unfinished test as failed.
func TestPackageTimeoutResultsSummary(t *testing.T) {
	t.Parallel()

	pkg := writePkg(t, multiPkgDir(t), "hang", hangSrc)
	summaryPath := filepath.Join(t.TempDir(), "summary.md")
	cmd := cmdTestwrapper(t, pkg, "-timeout=5s")
	cmd.Env = append(cmd.Env,
		"GITHUB_STEP_SUMMARY="+summaryPath,
		"TS_TESTWRAPPER_RESULTS_SUMMARY=1",
	)
	out, err := cmd.CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("got exit code %d, want 1 (err: %v) with output:\n%s", code, err, out)
	}
	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("reading summary: %v\noutput:\n%s", err, out)
	}
	for _, want := range []string{
		"_No flaky tests detected._",
		"| ❌ | `TestHang` |",
		"| ❌ | `TestParallel` |",
		"| ❌ | `TestFails` |",
		"results may be partial",
	} {
		if !bytes.Contains(summary, []byte(want)) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
}

// TestPackageFailureNotHiddenByFlake covers a package that fails with no
// failed test (here TestMain exits non-zero) in the same go test invocation
// as a flaky test in another package. The flaky test in the other package
// must not hide the package failure.
func TestPackageFailureNotHiddenByFlake(t *testing.T) {
	t.Parallel()

	dir := multiPkgDir(t)
	flakyPkg := writePkg(t, dir, "flaky", flakySrc)
	exitPkg := writePkg(t, dir, "mainexit", `package mainexit_test

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	m.Run()
	os.Exit(1)
}

func TestPass(t *testing.T) {}
`)

	// go test prints package results in command-line order, so the wrapper
	// sees the failure of the flaky package before the failure of the other
	// package.
	out, err := cmdTestwrapper(t, flakyPkg, exitPkg).CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("got exit code %d, want 1 (err: %v) with output:\n%s", code, err, out)
	}
	for _, want := range []string{
		"FAIL\t" + importPath(exitPkg),
		"[retry 1] " + importPath(flakyPkg) + ".TestFlaky: PASS",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// TestPackageFailureNotHiddenByRetry covers a package that fails after its
// tests run (here TestMain exits non-zero) and also has a flaky test. The
// flaky test passes on retry, but go test still fails, so the wrapper must
// exit non-zero.
func TestPackageFailureNotHiddenByRetry(t *testing.T) {
	t.Parallel()

	pkg := writePkg(t, multiPkgDir(t), "mainexit", `package mainexit_test

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	m.Run()
	os.Exit(1)
}

func TestFlaky(t *testing.T) {
	if os.Getenv("TS_TESTWRAPPER_ATTEMPT") == "1" {
		t.Fatal("failing on the first attempt so the wrapper retries")
	}
}
`)

	out, err := cmdTestwrapper(t, pkg).CombinedOutput()
	if code, ok := errExitCode(err); !ok || code != 1 {
		t.Fatalf("got exit code %d, want 1 (err: %v) with output:\n%s", code, err, out)
	}
	for _, want := range []string{
		"[retry 1] " + importPath(pkg) + ".TestFlaky: PASS",
		"testwrapper: " + importPath(pkg) + ".TestFlaky passed on retry, but go test failed; failing the run",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
