// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// testwrapper is a wrapper for go test that automatically retries failing
// tests to detect flakiness.
//
// Any failed test is treated as potentially flaky and re-run within a per-test
// time budget (see the perAttempt* and perTestBudget constants). A test that
// fails and then later passes is reported as flaky. A test that never passes
// within the budget is a real failure and causes a non-zero exit.
//
// The flakytest package's Mark API is no longer required for retries — it is
// kept for explicit issue tracking and for the TS_SKIP_FLAKY_TESTS skip
// behavior.
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
)

// Per-test retry policy. See package doc comment.
const (
	// perAttemptCap is the upper bound on the per-retry-attempt -timeout we set
	// when running a single failed test.
	perAttemptCap = 5 * time.Minute
	// perAttemptFloor is the lower bound on the per-retry-attempt -timeout, to
	// give the test binary time to start.
	perAttemptFloor = 30 * time.Second
	// maxRetries caps the number of retry attempts for a single test. It
	// guards against re-running a very fast test thousands of times within
	// perTestBudget.
	maxRetries = 10

	// raceDetectorMarkerLine is the first line of every Go race
	// detector report, emitted at column 0. We look for it as a
	// whole line (not as a substring) so that we don't false-fire
	// on tests that legitimately print the same text indented in
	// their own logs — for example, this package's own race tests,
	// which exec a child testwrapper and dump its captured output.
	raceDetectorMarkerLine = "WARNING: DATA RACE\n"
)

// Tunables for the per-test retry budget. These default to production values
// but can be overridden via env vars, primarily for tests of testwrapper
// itself.
var (
	// perTestBudget is the total wall-clock time we are willing to spend
	// retrying a single test before giving up. Override via
	// TS_TESTWRAPPER_BUDGET (a time.Duration string).
	perTestBudget = envDuration("TS_TESTWRAPPER_BUDGET", 10*time.Minute)
	// minRetries is the minimum number of retry attempts we make for a failed
	// test, regardless of perTestBudget. Override via TS_TESTWRAPPER_MIN_RETRIES.
	minRetries = envInt("TS_TESTWRAPPER_MIN_RETRIES", 2)
	// maxRetryTime is the maximum wall-clock time we are willing to spend on the
	// whole retry phase. It ensures a run with many flakes or real failures
	// doesn't block for an unreasonable amount of time. Override via
	// TS_TESTWRAPPER_MAX_RETRY_TIME (a time.Duration string).
	maxRetryTime = envDuration("TS_TESTWRAPPER_MAX_RETRY_TIME", 10*time.Minute)
)

func envDuration(key string, def time.Duration) time.Duration {
	s := os.Getenv(key)
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		log.Panicf("invalid %s=%q: %v", key, s, err)
	}
	return d
}

func envInt(key string, def int) int {
	s := os.Getenv(key)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		log.Panicf("invalid %s=%q: %v", key, s, err)
	}
	return n
}

// flakeUnknownIssueSlug is the trailing path of the fake GitHub issue URL we
// record for tests that turned out flaky but were not explicitly marked with
// flakytest.Mark. flakeapp records this as a flake occurrence with no real
// issue.
const flakeUnknownIssueSlug = "/issues/UNKNOWN"

// testOutcome is the outcome of a single test (or package) run. Its string
// values match the Action field in `go test -json` output.
type testOutcome string

const (
	outcomeUnknown testOutcome = ""
	outcomePass    testOutcome = "pass"
	outcomeFail    testOutcome = "fail"
	outcomeSkip    testOutcome = "skip"
)

type testAttempt struct {
	pkg           string      // "tailscale.com/types/key"
	testName      string      // "TestFoo"
	outcome       testOutcome // outcomePass, outcomeFail, outcomeSkip, or outcomeUnknown
	cached        bool        // whether package-level (non-testName specific) was pass due to being cached
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

// failedTest tracks per-test state across the retry phase.
type failedTest struct {
	pkg, testName     string
	firstFailDuration time.Duration
	issueURL          string // non-empty iff the test called flakytest.Mark

	attempts          int           // number of retry attempts run so far
	totalRetryElapsed time.Duration // total time spent across retry attempts
	everPassed        bool          // a retry attempt passed
}

// packageTests describes what to run.
// It's also JSON-marshalled to output for analysis tools to parse,
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
			ch <- &testAttempt{pkg: pt.Pattern, outcome: outcomeSkip, pkgFinished: true}
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
					if test.testName != "" && test.outcome == outcomeUnknown {
						test.outcome = outcomeFail
						ch <- test
					}
				}
				outcome := testOutcome(goOutput.Action)
				if goOutput.Action == "build-fail" {
					outcome = outcomeFail
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
			pkgTests[testName].outcome = testOutcome(goOutput.Action)
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

// runOneTest runs a single test in a single package via `go test -run` with a
// per-attempt -timeout. It returns the test's outcome (outcomePass /
// outcomeFail / outcomeSkip), the wall-clock time spent on this attempt
// (used for the per-test retry budget), and any captured test logs.
//
// On panic, timeout, or any other failure mode where the test does not emit a
// pass/fail/skip JSON event, outcome is reported as outcomeFail.
func runOneTest(ctx context.Context, pkg, testName string, perAttemptTimeout time.Duration, attemptNum int, goTestArgs, testArgs []string) (outcome testOutcome, wallDur time.Duration, logs bytes.Buffer, err error) {
	goTestArgs, perAttemptTimeout = extractTimeout(goTestArgs, perAttemptTimeout)
	testArgs, perAttemptTimeout = extractTimeout(testArgs, perAttemptTimeout)
	args := []string{"test", "-json"}
	args = append(args, goTestArgs...)
	args = append(args, "-timeout", perAttemptTimeout.String())
	args = append(args, pkg)
	args = append(args, "--run", "^("+regexp.QuoteMeta(testName)+")$")
	args = append(args, testArgs...)

	if debug {
		fmt.Println("running", strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	// Strip TS_TEST_SHARD so the child doesn't try to shard inside a
	// single-test retry — we are telling it exactly what to run.
	cmd.Env = slices.DeleteFunc(os.Environ(), func(s string) bool {
		return strings.HasPrefix(s, "TS_TEST_SHARD=")
	})
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%d", flakytest.FlakeAttemptEnv, attemptNum))
	r, perr := cmd.StdoutPipe()
	if perr != nil {
		return "", 0, logs, fmt.Errorf("stdout pipe: %w", perr)
	}
	defer r.Close()
	cmd.Stderr = os.Stderr

	wallStart := time.Now()
	if err := cmd.Start(); err != nil {
		return "", 0, logs, fmt.Errorf("starting go test: %w", err)
	}

	s := bufio.NewScanner(r)
	for s.Scan() {
		var ev goTestOutput
		if err := json.Unmarshal(s.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Test == "" {
			continue // package-level events ignored for single-test runs
		}
		// Collapse subtests to parent.
		parent, _, _ := strings.Cut(ev.Test, "/")
		if parent != testName {
			continue
		}
		switch ev.Action {
		case "pass", "fail", "skip":
			if ev.Test == testName {
				outcome = testOutcome(ev.Action)
			}
		case "output":
			logs.WriteString(ev.Output)
		}
	}
	waitErr := cmd.Wait()
	wallDur = time.Since(wallStart)
	if scanErr := s.Err(); scanErr != nil && err == nil {
		err = fmt.Errorf("reading go test stdout: %w", scanErr)
	}
	if outcome == outcomeUnknown {
		// Test never emitted a pass/fail/skip — likely a panic, timeout, or
		// build error. Treat as fail.
		outcome = outcomeFail
	}
	if waitErr != nil && err == nil && outcome == outcomePass {
		// A non-zero exit when outcome==outcomePass is unexpected; surface it.
		err = waitErr
	}
	return outcome, wallDur, logs, err
}

// extractTimeout returns args with any -timeout / -test.timeout flags
// stripped, and the smaller of cap and the user-supplied timeout (if any).
// This lets retries use the testwrapper-computed per-attempt timeout, but
// never exceed an explicit -timeout the user passed on the command line.
func extractTimeout(args []string, cap time.Duration) (stripped []string, t time.Duration) {
	t = cap
	stripped = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		bare := strings.TrimLeft(a, "-")
		name, val, hasEq := strings.Cut(bare, "=")
		if name == "timeout" || name == "test.timeout" {
			var raw string
			if hasEq {
				raw = val
			} else if i+1 < len(args) {
				raw = args[i+1]
				i++
			}
			if d, err := time.ParseDuration(raw); err == nil && d < t {
				t = d
			}
			continue
		}
		stripped = append(stripped, a)
	}
	return stripped, t
}

// computePerAttemptTimeout returns the -timeout we use for each retry attempt
// of a test that first failed in firstFail.
//
// It is the smaller of perAttemptCap (5 min) and 1.5*firstFail, but never
// smaller than perAttemptFloor (30 s).
func computePerAttemptTimeout(firstFail time.Duration) time.Duration {
	t := time.Duration(float64(firstFail) * 1.5)
	return max(perAttemptFloor, min(perAttemptCap, t))
}

// retryFailedTest runs the per-test retry loop for ft. It updates ft in place.
func retryFailedTest(ctx context.Context, ft *failedTest, goTestArgs, testArgs []string, deadline time.Time) {
	perAttempt := computePerAttemptTimeout(ft.firstFailDuration)
	for {
		if ft.everPassed {
			return
		}
		if ft.attempts >= maxRetries {
			return
		}
		if ft.attempts >= minRetries && ft.totalRetryElapsed >= perTestBudget {
			return
		}
		if remaining := time.Until(deadline); remaining < perAttempt {
			// perAttempt represents a reasonable guess of how long the test might take
			// to run, so don't even attempt to retry a test that is likely to take us
			// past our overall deadline.
			log.Printf("testwrapper: not retrying %s.%s because its timeout (%.1fs) would exceed the remaining max retry time (%.1fs)",
				ft.pkg, ft.testName, perAttempt.Seconds(), remaining.Seconds())
			return
		}

		// FlakeAttemptEnv is 1-indexed counting the first pass as attempt 1.
		// Retry attempt N is FlakeAttemptEnv = 1 + N.
		attemptNum := 1 + ft.attempts + 1
		outcome, dur, logs, err := runOneTest(ctx, ft.pkg, ft.testName, perAttempt, attemptNum, goTestArgs, testArgs)
		ft.attempts++
		ft.totalRetryElapsed += dur

		fmt.Printf("    [retry %d] %s.%s: %s (%.3fs)\n",
			ft.attempts, ft.pkg, ft.testName, strings.ToUpper(string(outcome)), dur.Seconds())
		if err != nil {
			log.Printf("testwrapper: error running %s.%s: %v", ft.pkg, ft.testName, err)
		}
		if testingVerbose || outcome == outcomeFail {
			io.Copy(os.Stdout, &logs)
		}
		if outcome == outcomePass {
			ft.everPassed = true
		}
	}
}

// detectRepo returns the GitHub "owner/repo" we're running in, used in the
// fake issue URL recorded for unmarked flaky tests.
//
// It checks GITHUB_REPOSITORY (set by GitHub Actions), then `git config --get
// remote.origin.url`, then falls back to "tailscale/tailscale".
func detectRepo() string {
	if r := os.Getenv("GITHUB_REPOSITORY"); r != "" {
		return r
	}
	out, err := exec.Command("git", "config", "--get", "remote.origin.url").Output()
	if err == nil {
		if r := parseGitRemote(strings.TrimSpace(string(out))); r != "" {
			return r
		}
	}
	return "tailscale/tailscale"
}

// parseGitRemote pulls "owner/repo" out of common git remote URL forms:
//   - git@github.com:owner/repo.git
//   - https://github.com/owner/repo.git
//   - https://github.com/owner/repo
func parseGitRemote(url string) string {
	url = strings.TrimSuffix(url, ".git")
	// SSH form
	if rest, ok := strings.CutPrefix(url, "git@github.com:"); ok {
		return rest
	}
	// HTTPS form
	for _, p := range []string{"https://github.com/", "http://github.com/"} {
		if rest, ok := strings.CutPrefix(url, p); ok {
			return rest
		}
	}
	return ""
}

// fakeIssueURL returns the fake GitHub issue URL we record for unmarked tests
// that turn out to be flaky.
func fakeIssueURL(repo string) string {
	return "https://github.com/" + repo + flakeUnknownIssueSlug
}

// writeFlakeSummary appends a markdown summary of flaky tests to path,
// creating it if needed. In practice path is the GitHub Actions runner's
// $GITHUB_STEP_SUMMARY, which testwrapper auto-detects. It logs and
// continues on errors, as a CI write failure should not poison the test
// run's exit status.
func writeFlakeSummary(path string, flaky []*failedTest, repo string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("testwrapper: opening summary file %s: %v", path, err)
		return
	}
	defer f.Close()
	if len(flaky) == 0 {
		fmt.Fprintln(f, "_No flaky tests detected._")
		return
	}
	fmt.Fprintln(f, "### Flaky tests detected")
	fmt.Fprintln(f)
	fmt.Fprintln(f, "Tests that failed at least once and then passed on retry. Rows tagged 🆕 were not annotated with flakytest.Mark; testwrapper auto-detected the flake.")
	fmt.Fprintln(f)
	fmt.Fprintln(f, "| Package | Test | Retries | Retry time | Issue |")
	fmt.Fprintln(f, "|---------|------|--------:|-----------:|-------|")
	for _, ft := range flaky {
		url := ft.issueURL
		if url == "" {
			url = fakeIssueURL(repo)
		}
		var tag string
		if ft.issueURL == "" {
			tag = " 🆕"
		}
		fmt.Fprintf(f, "| `%s` | `%s`%s | %d | %.1fs | [link](%s) |\n",
			ft.pkg, ft.testName, tag, ft.attempts, ft.totalRetryElapsed.Seconds(), url)
	}
}

// buildPackageTests groups failedTests by package into the wire format
// flakeapp expects.
//
// If fakeRepo is non-empty, tests with no real issue URL (i.e. not marked via
// flakytest.Mark) get a fake URL of the form
// https://github.com/{fakeRepo}/issues/UNKNOWN. If fakeRepo is empty, those
// tests are simply omitted from the IssueURLs map.
func buildPackageTests(fts []*failedTest, fakeRepo string) []packageTests {
	byPkg := map[string][]*failedTest{}
	for _, ft := range fts {
		byPkg[ft.pkg] = append(byPkg[ft.pkg], ft)
	}
	pkgs := make([]string, 0, len(byPkg))
	for p := range byPkg {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	out := make([]packageTests, 0, len(pkgs))
	for _, p := range pkgs {
		group := byPkg[p]
		slices.SortFunc(group, func(a, b *failedTest) int { return strings.Compare(a.testName, b.testName) })
		pt := packageTests{Pattern: p, IssueURLs: map[string]string{}}
		for _, ft := range group {
			pt.Tests = append(pt.Tests, ft.testName)
			url := ft.issueURL
			if url == "" && fakeRepo != "" {
				url = fakeIssueURL(fakeRepo)
			}
			if url != "" {
				pt.IssueURLs[ft.testName] = url
			}
		}
		out = append(out, pt)
	}
	return out
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
	repo := detectRepo()

	printPkgOutcome := func(pkg string, outcome testOutcome, cached bool, testDur time.Duration) {
		if pkg == "" {
			return // We reach this path on a build error.
		}
		if outcome == outcomeSkip {
			fmt.Printf("?\t%s [skipped/no tests] \n", pkg)
			return
		}
		label := string(outcome)
		if outcome == outcomePass {
			label = "ok"
		}
		if outcome == outcomeFail {
			label = "FAIL"
		}
		var lastCol string
		if cached {
			lastCol = "(cached)"
		} else {
			lastCol = fmt.Sprintf("%.3fs", testDur.Seconds())
		}
		fmt.Printf("%s\t%s\t%v\n", label, pkg, lastCol)
	}

	// First pass: run every package once, collect failed tests for retry.
	var failed []*failedTest
	var pkgFatal bool // a package produced a non-test fatal (build error, etc.)
	for _, pkgPattern := range packages {
		pt := &packageTests{Pattern: pkgPattern}
		ch := make(chan *testAttempt)
		runErrCh := make(chan error, 1)
		go func() {
			defer close(runErrCh)
			runErrCh <- runTests(ctx, 1, pt, goTestArgs, testArgs, ch)
		}()

		// Collect failed tests in this package on the side; we use the count
		// when a package reports a fail to decide if the failure is explained
		// by retryable test failures or is a separate package-level fatal.
		var pkgFailedTests []*failedTest
		for tr := range ch {
			// Go assigns the package name "command-line-arguments" when you
			// `go test FILE` rather than `go test PKG`. It's more
			// convenient for us to specify files in tests, so fix tr.pkg
			// so that subsequent testwrapper attempts run correctly.
			if tr.pkg == "command-line-arguments" {
				tr.pkg = packages[0]
			}
			if tr.pkgFinished {
				if tr.raceDetected {
					// A data race is never something we want to paper
					// over by retrying flaky tests in the package: the
					// race indicates a real bug that may not even be
					// in the failing test, and a retry could hide it.
					// Drop any retry plans for this pkg and fail fast.
					pkgFailedTests = nil
					pkgFatal = true
				}
				if testingVerbose || tr.outcome == outcomeFail {
					io.Copy(os.Stdout, &tr.logs)
				}
				if tr.outcome == outcomeFail && len(pkgFailedTests) == 0 {
					// Package failed but no test failed (e.g. the package
					// timed out, or a build error). Not retryable per-test.
					pkgFatal = true
				}
				printPkgOutcome(tr.pkg, tr.outcome, tr.cached, tr.end.Sub(tr.start))
				continue
			}
			if testingVerbose || tr.outcome == outcomeFail {
				io.Copy(os.Stdout, &tr.logs)
			}
			if tr.outcome != outcomeFail {
				continue
			}
			pkgFailedTests = append(pkgFailedTests, &failedTest{
				pkg:               tr.pkg,
				testName:          tr.testName,
				firstFailDuration: tr.end.Sub(tr.start),
				issueURL:          tr.issueURL, // real if Mark()'d, else "".
			})
		}
		failed = append(failed, pkgFailedTests...)
		if err := <-runErrCh; err != nil {
			if exit, ok := errors.AsType[*exec.ExitError](err); ok {
				if code := exit.ExitCode(); code > -1 && len(pkgFailedTests) == 0 {
					// Pure exec failure with no test-level failures to retry:
					// honor the original exit code.
					os.Exit(code)
				}
			} else {
				log.Printf("testwrapper: %s", err)
				pkgFatal = true
			}
		}
	}

	// Second pass: retry each failed test serially with its per-test budget.
	if len(failed) > 0 {
		deadline := time.Now().Add(maxRetryTime)
		fmt.Printf("\n\nRetrying %d failed test(s) to detect flakiness...\n\n", len(failed))
		for _, ft := range failed {
			retryFailedTest(ctx, ft, goTestArgs, testArgs, deadline)
		}
	}

	// Summarize and exit.
	var flaky, permanent []*failedTest
	for _, ft := range failed {
		if ft.everPassed {
			flaky = append(flaky, ft)
		} else {
			permanent = append(permanent, ft)
		}
	}
	if len(flaky) > 0 {
		j, _ := json.Marshal(buildPackageTests(flaky, repo))
		fmt.Printf("\nflakytest failures JSON: %s\n", j)
	}
	if path := os.Getenv("GITHUB_STEP_SUMMARY"); path != "" {
		writeFlakeSummary(path, flaky, repo)
	}
	if len(permanent) > 0 {
		j, _ := json.Marshal(buildPackageTests(permanent, ""))
		fmt.Printf("\npermanent test failures JSON: %s\n", j)
	}

	if pkgFatal || len(permanent) > 0 {
		os.Exit(1)
	}
}
