// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// testwrapper is a wrapper for retrying flaky tests. It is an alternative to
// `go test` and re-runs failed marked flaky tests (using the flakytest pkg). It
// takes different arguments than go test and requires the first positional
// argument to be the pattern to test.
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/util/slicesx"
)

const (
	maxAttempts = 3

	// raceDetectorMarkerLine is the first line of every Go race
	// detector report, emitted at column 0. We look for it as a
	// whole line (not as a substring) so that we don't false-fire
	// on tests that legitimately print the same text indented in
	// their own logs — for example, this package's own race tests,
	// which exec a child testwrapper and dump its captured output.
	raceDetectorMarkerLine = "WARNING: DATA RACE\n"
)

type testAttempt struct {
	pkg           string // "tailscale.com/types/key"
	testName      string // "TestFoo"
	outcome       string // "pass", "fail", "skip"
	cached        bool   // whether package-level (non-testName specific) was pass due to being cached
	logs          bytes.Buffer
	start, end    time.Time
	isMarkedFlaky bool   // set if the test is marked as flaky
	issueURL      string // set if the test is marked as flaky
	// raceDetected is true on a per-test event if that test's output
	// contained a race report, and true on a pkgFinished event if any
	// test in the package -- or the package's own output -- did.
	raceDetected bool

	pkgFinished bool
}

// packageTests describes what to run.
// It's also JSON-marshalled to output for analysys tools to parse
// so the fields are all exported.
// TODO(bradfitz): move this type to its own types package?
type packageTests struct {
	// Pattern is the package Pattern to run.
	// Must be a single Pattern, not a list of patterns.
	Pattern string // "./...", "./types/key"
	// Tests is a list of Tests to run. If empty, all Tests in the package are
	// run.
	Tests []string // ["TestFoo", "TestBar"]
	// IssueURLs maps from a test name to a URL tracking its flake.
	IssueURLs map[string]string // "TestFoo" => "https://github.com/foo/bar/issue/123"
}

type goTestOutput struct {
	Time       time.Time
	Action     string
	ImportPath string
	Package    string
	Test       string
	Output     string
}

var debug = os.Getenv("TS_TESTWRAPPER_DEBUG") != ""

// testsForShard returns the test names in pkg that belong to the given shard
// spec (e.g. "2/3"). It uses "go list -json" to find test source files (no
// compilation) and scans them for top-level test function names, assigning
// each to a shard by hashing. Returns nil if the spec is invalid or if
// listing fails (the main run will surface the error).
func testsForShard(ctx context.Context, pkg, shardSpec string) ([]string, error) {
	a, b, ok := strings.Cut(shardSpec, "/")
	if !ok {
		return nil, nil
	}
	wantShard, err := strconv.Atoi(a)
	if err != nil || wantShard < 1 {
		return nil, nil
	}
	shards, err := strconv.Atoi(b)
	if err != nil || shards < 1 {
		return nil, nil
	}

	out, err := exec.CommandContext(ctx, "go", "list", "-json", pkg).Output()
	if err != nil {
		// Errors will be surfaced by the main test run.
		return nil, nil
	}

	type pkgJSON struct {
		Dir          string
		TestGoFiles  []string
		XTestGoFiles []string
	}

	seen := map[string]bool{}
	var result []string

	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var p pkgJSON
		if err := dec.Decode(&p); err != nil {
			break
		}
		for _, f := range append(p.TestGoFiles, p.XTestGoFiles...) {
			names, err := testFuncNames(filepath.Join(p.Dir, f))
			if err != nil {
				continue
			}
			for _, name := range names {
				if seen[name] {
					continue
				}
				seen[name] = true
				h := fnv.New32a()
				io.WriteString(h, name)
				if int(h.Sum32()%uint32(shards)) == wantShard-1 {
					result = append(result, name)
				}
			}
		}
	}
	return result, nil
}

// testFuncNames scans a Go source file and returns the names of all top-level
// test functions (Test*, Benchmark*, Example*, Fuzz*).
func testFuncNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rest, ok := strings.CutPrefix(sc.Text(), "func ")
		if !ok {
			continue
		}
		for _, prefix := range []string{"Test", "Benchmark", "Example", "Fuzz"} {
			if strings.HasPrefix(rest, prefix) {
				if i := strings.IndexByte(rest, '('); i > 0 {
					names = append(names, rest[:i])
				}
				break
			}
		}
	}
	return names, sc.Err()
}

// runTests runs the tests in pt and sends the results on ch. It sends a
// testAttempt for each test and a final testAttempt per pkg with pkgFinished
// set to true. Package build errors will not emit a testAttempt (as no valid
// JSON is produced) but the [os/exec.ExitError] will be returned.
// It calls close(ch) when it's done.
func runTests(ctx context.Context, attempt int, pt *packageTests, goTestArgs, testArgs []string, ch chan<- *testAttempt) error {
	defer close(ch)
	args := []string{"test"}
	args = append(args, goTestArgs...)
	args = append(args, pt.Pattern)
	if len(pt.Tests) > 0 {
		// Specific tests requested (e.g. flaky test retry).
		runArg := strings.Join(pt.Tests, "|")
		args = append(args, "--run", runArg)
	} else if shardSpec := os.Getenv("TS_TEST_SHARD"); shardSpec != "" {
		// Automatic test-name sharding: list tests and filter by hash.
		shardTests, err := testsForShard(ctx, pt.Pattern, shardSpec)
		if err != nil {
			return err
		}
		if len(shardTests) == 0 {
			ch <- &testAttempt{pkg: pt.Pattern, outcome: "skip", pkgFinished: true}
			return nil
		}
		quoted := make([]string, len(shardTests))
		for i, name := range shardTests {
			quoted[i] = regexp.QuoteMeta(name)
		}
		args = append(args, "--run", "^("+strings.Join(quoted, "|")+")$")
	}
	args = append(args, testArgs...)
	args = append(args, "-json")
	if debug {
		fmt.Println("running", strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	r, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("error creating stdout pipe: %v", err)
	}
	defer r.Close()
	cmd.Stderr = os.Stderr

	cmd.Env = slices.DeleteFunc(os.Environ(), func(s string) bool {
		return strings.HasPrefix(s, "TS_TEST_SHARD=")
	})
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%d", flakytest.FlakeAttemptEnv, attempt))

	if err := cmd.Start(); err != nil {
		log.Printf("error starting test: %v", err)
		os.Exit(1)
	}

	pkgCached := map[string]bool{}

	s := bufio.NewScanner(r)
	resultMap := make(map[string]map[string]*testAttempt) // pkg -> test -> testAttempt
	for s.Scan() {
		var goOutput goTestOutput
		if err := json.Unmarshal(s.Bytes(), &goOutput); err != nil {
			return fmt.Errorf("failed to parse go test output %q: %w", s.Bytes(), err)
		}
		pkg := cmp.Or(
			goOutput.Package,
			"build:"+goOutput.ImportPath, // can be "./cmd" while Package is "tailscale.com/cmd" so use separate namespace
		)
		pkgTests := resultMap[pkg]
		if pkgTests == nil {
			pkgTests = map[string]*testAttempt{
				"": {}, // Used for start time and build logs.
			}
			resultMap[pkg] = pkgTests
		}
		if goOutput.Test == "" {
			// Detect output lines like:
			// ok  \ttailscale.com/cmd/testwrapper\t(cached)
			// ok  \ttailscale.com/cmd/testwrapper\t(cached)\tcoverage: 17.0% of statements
			if goOutput.Package != "" && strings.Contains(goOutput.Output, fmt.Sprintf("%s\t(cached)", goOutput.Package)) {
				pkgCached[goOutput.Package] = true
			}
			switch goOutput.Action {
			case "start":
				pkgTests[""].start = goOutput.Time
			case "build-output":
				pkgTests[""].logs.WriteString(goOutput.Output)
			case "build-fail", "fail", "pass", "skip":
				for _, test := range pkgTests {
					if test.testName != "" && test.outcome == "" {
						test.outcome = "fail"
						ch <- test
					}
				}
				outcome := goOutput.Action
				if outcome == "build-fail" {
					outcome = "fail"
				}
				pkgTests[""].logs.WriteString(goOutput.Output)
				// If a data race was detected anywhere in this
				// package's output -- whether at the package level or
				// attributed to a specific test -- consolidate all
				// per-test logs into the package-level logs so the
				// full race report is visible regardless of which
				// test test2json happened to attribute it to. The
				// pkgFinished testAttempt also carries raceDetected
				// so the main loop can suppress flaky-test retries.
				raceDetected := pkgTests[""].raceDetected
				if !raceDetected {
					for _, t := range pkgTests {
						if t.raceDetected {
							raceDetected = true
							break
						}
					}
				}
				if raceDetected {
					var ts []*testAttempt
					for _, t := range pkgTests {
						if t.testName != "" && t.logs.Len() > 0 {
							ts = append(ts, t)
						}
					}
					slices.SortFunc(ts, func(a, b *testAttempt) int {
						return a.start.Compare(b.start)
					})
					for _, t := range ts {
						pkgTests[""].logs.Write(t.logs.Bytes())
					}
				}
				ch <- &testAttempt{
					pkg:          goOutput.Package,
					outcome:      outcome,
					start:        pkgTests[""].start,
					end:          goOutput.Time,
					logs:         pkgTests[""].logs,
					pkgFinished:  true,
					cached:       pkgCached[goOutput.Package],
					raceDetected: raceDetected,
				}
			case "output":
				// Capture all output from the package except for the final
				// "FAIL    tailscale.io/control    0.684s" line, as
				// printPkgOutcome will output a similar line
				if !strings.HasPrefix(goOutput.Output, fmt.Sprintf("FAIL\t%s\t", goOutput.Package)) {
					pkgTests[""].logs.WriteString(goOutput.Output)
					if goOutput.Output == raceDetectorMarkerLine {
						pkgTests[""].raceDetected = true
					}
				}
			}

			continue
		}
		testName := goOutput.Test
		if test, _, isSubtest := strings.Cut(goOutput.Test, "/"); isSubtest {
			testName = test
			if goOutput.Action == "output" {
				resultMap[pkg][testName].logs.WriteString(goOutput.Output)
				if goOutput.Output == raceDetectorMarkerLine {
					resultMap[pkg][testName].raceDetected = true
				}
			}
			continue
		}
		switch goOutput.Action {
		case "start":
			// ignore
		case "run":
			pkgTests[testName] = &testAttempt{
				pkg:      pkg,
				testName: testName,
				start:    goOutput.Time,
			}
		case "skip", "pass", "fail":
			pkgTests[testName].end = goOutput.Time
			pkgTests[testName].outcome = goOutput.Action
			ch <- pkgTests[testName]
		case "output":
			if suffix, ok := strings.CutPrefix(strings.TrimSpace(goOutput.Output), flakytest.FlakyTestLogMessage); ok {
				pkgTests[testName].isMarkedFlaky = true
				pkgTests[testName].issueURL = strings.TrimPrefix(suffix, ": ")
			} else {
				pkgTests[testName].logs.WriteString(goOutput.Output)
				if goOutput.Output == raceDetectorMarkerLine {
					pkgTests[testName].raceDetected = true
				}
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		return err
	}
	if err := s.Err(); err != nil {
		return fmt.Errorf("reading go test stdout: %w", err)
	}
	return nil
}

func main() {
	goTestArgs, packages, testArgs, err := splitArgs(os.Args[1:])
	if err != nil {
		log.Fatal(err)
		return
	}
	if len(packages) == 0 {
		fmt.Println("testwrapper: no packages specified")
		return
	}

	// As a special case, if the packages looks like "sharded:1/2" then shell out to
	// ./tool/listpkgs to cut up the package list pieces for each sharded builder.
	if nOfM, ok := strings.CutPrefix(packages[0], "sharded:"); ok && len(packages) == 1 {
		out, err := exec.Command("go", "run", "tailscale.com/tool/listpkgs", "-shard", nOfM, "./...").Output()
		if err != nil {
			log.Fatalf("failed to list packages for sharded test: %v", err)
		}
		packages = strings.Split(strings.TrimSpace(string(out)), "\n")
	}

	ctx := context.Background()
	type nextRun struct {
		tests   []*packageTests
		attempt int // starting at 1
	}
	firstRun := &nextRun{
		attempt: 1,
	}
	for _, pkg := range packages {
		firstRun.tests = append(firstRun.tests, &packageTests{Pattern: pkg})
	}
	toRun := []*nextRun{firstRun}
	printPkgOutcome := func(pkg, outcome string, cached bool, attempt int, testDur time.Duration) {
		if pkg == "" {
			return // We reach this path on a build error.
		}
		if outcome == "skip" {
			fmt.Printf("?\t%s [skipped/no tests] \n", pkg)
			return
		}
		if outcome == "pass" {
			outcome = "ok"
		}
		if outcome == "fail" {
			outcome = "FAIL"
		}
		if attempt > 1 {
			fmt.Printf("%s\t%s\t%.3fs\t[attempt=%d]\n", outcome, pkg, testDur.Seconds(), attempt)
			return
		}
		var lastCol string
		if cached {
			lastCol = "(cached)"
		} else {
			lastCol = fmt.Sprintf("%.3fs", testDur.Seconds())
		}
		fmt.Printf("%s\t%s\t%v\n", outcome, pkg, lastCol)
	}

	for len(toRun) > 0 {
		var thisRun *nextRun
		thisRun, toRun = toRun[0], toRun[1:]

		if thisRun.attempt > maxAttempts {
			fmt.Println("max attempts reached")
			os.Exit(1)
		}
		if thisRun.attempt > 1 {
			j, _ := json.Marshal(thisRun.tests)
			fmt.Printf("\n\nAttempt #%d: Retrying flaky tests:\n\nflakytest failures JSON: %s\n\n", thisRun.attempt, j)
		}

		fatalFailures := make(map[string]struct{}) // pkg.Test key
		toRetry := make(map[string][]*testAttempt) // pkg -> tests to retry
		for _, pt := range thisRun.tests {
			ch := make(chan *testAttempt)
			runErr := make(chan error, 1)
			go func() {
				defer close(runErr)
				runErr <- runTests(ctx, thisRun.attempt, pt, goTestArgs, testArgs, ch)
			}()

			var failed bool
			for tr := range ch {
				// Go assigns the package name "command-line-arguments" when you
				// `go test FILE` rather than `go test PKG`. It's more
				// convenient for us to to specify files in tests, so fix tr.pkg
				// so that subsequent testwrapper attempts run correctly.
				if tr.pkg == "command-line-arguments" {
					tr.pkg = packages[0]
				}
				if tr.pkgFinished {
					if tr.raceDetected {
						// A data race is never something we want to
						// paper over by retrying flaky tests in the
						// package: the race indicates a real bug
						// that may not even be in the failing test,
						// and a retry could hide it. Discard any
						// retry plans for this pkg and fail fast.
						delete(toRetry, tr.pkg)
						failed = true
					}
					if tr.outcome == "fail" && len(toRetry[tr.pkg]) == 0 {
						// If a package fails and we don't have any tests to
						// retry, then we should fail. This typically happens
						// when a package times out.
						failed = true
					}
					if testingVerbose || tr.outcome == "fail" {
						// Output package-level output which is where e.g.
						// panics outside tests will be printed
						io.Copy(os.Stdout, &tr.logs)
					}
					printPkgOutcome(tr.pkg, tr.outcome, tr.cached, thisRun.attempt, tr.end.Sub(tr.start))
					continue
				}
				if testingVerbose || tr.outcome == "fail" {
					io.Copy(os.Stdout, &tr.logs)
				}
				if tr.outcome != "fail" {
					continue
				}
				if tr.isMarkedFlaky {
					toRetry[tr.pkg] = append(toRetry[tr.pkg], tr)
				} else {
					fatalFailures[tr.pkg+"."+tr.testName] = struct{}{}
					failed = true
				}
			}
			if failed {
				fmt.Println("\n\nNot retrying flaky tests because non-flaky tests failed.")

				// Print the list of non-flakytest failures.
				// We will later analyze the retried GitHub Action runs to see
				// if non-flakytest failures succeeded upon retry. This will
				// highlight tests which are flaky but not yet flagged as such.
				if len(fatalFailures) > 0 {
					tests := slicesx.MapKeys(fatalFailures)
					sort.Strings(tests)
					j, _ := json.Marshal(tests)
					fmt.Printf("non-flakytest failures: %s\n", j)
				}
				fmt.Println()
				os.Exit(1)
			}

			// If there's nothing to retry and no non-retryable tests have
			// failed then we've probably hit a build error.
			if err := <-runErr; len(toRetry) == 0 && err != nil {
				if exit, ok := errors.AsType[*exec.ExitError](err); ok {
					if code := exit.ExitCode(); code > -1 {
						os.Exit(exit.ExitCode())
					}
				}
				log.Printf("testwrapper: %s", err)
				os.Exit(1)
			}
		}
		if len(toRetry) == 0 {
			continue
		}
		pkgs := slicesx.MapKeys(toRetry)
		sort.Strings(pkgs)
		nextRun := &nextRun{
			attempt: thisRun.attempt + 1,
		}
		for _, pkg := range pkgs {
			tests := toRetry[pkg]
			slices.SortFunc(tests, func(a, b *testAttempt) int { return strings.Compare(a.testName, b.testName) })
			issueURLs := map[string]string{} // test name => URL
			var testNames []string
			for _, ta := range tests {
				issueURLs[ta.testName] = ta.issueURL
				testNames = append(testNames, ta.testName)
			}
			nextRun.tests = append(nextRun.tests, &packageTests{
				Pattern:   pkg,
				Tests:     testNames,
				IssueURLs: issueURLs,
			})
		}
		toRun = append(toRun, nextRun)
	}
}
