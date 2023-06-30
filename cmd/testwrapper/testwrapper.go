// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// testwrapper is a wrapper for retrying flaky tests. It is an alternative to
// `go test` and re-runs failed marked flaky tests (using the flakytest pkg). It
// takes different arguments than go test and requires the first positional
// argument to be the pattern to test.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"tailscale.com/cmd/testwrapper/flakytest"
)

const maxAttempts = 3

type testAttempt struct {
	name          testName
	outcome       string // "pass", "fail", "skip"
	logs          bytes.Buffer
	isMarkedFlaky bool // set if the test is marked as flaky
}

type testName struct {
	pkg  string // "tailscale.com/types/key"
	name string // "TestFoo"
}

type packageTests struct {
	// pattern is the package pattern to run.
	// Must be a single pattern, not a list of patterns.
	pattern string // "./...", "./types/key"
	// tests is a list of tests to run. If empty, all tests in the package are
	// run.
	tests []string // ["TestFoo", "TestBar"]
}

type goTestOutput struct {
	Time    time.Time
	Action  string
	Package string
	Test    string
	Output  string
}

var debug = os.Getenv("TS_TESTWRAPPER_DEBUG") != ""

func runTests(ctx context.Context, attempt int, pt *packageTests, otherArgs []string) []*testAttempt {
	args := []string{"test", "-json", pt.pattern}
	args = append(args, otherArgs...)
	if len(pt.tests) > 0 {
		runArg := strings.Join(pt.tests, "|")
		args = append(args, "-run", runArg)
	}
	if debug {
		fmt.Println("running", strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	r, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("error creating stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%d", flakytest.FlakeAttemptEnv, attempt))

	if err := cmd.Start(); err != nil {
		log.Printf("error starting test: %v", err)
		os.Exit(1)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		cmd.Wait()
	}()

	jd := json.NewDecoder(r)
	resultMap := make(map[testName]*testAttempt)
	var out []*testAttempt
	for {
		var goOutput goTestOutput
		if err := jd.Decode(&goOutput); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				break
			}
			panic(err)
		}
		if goOutput.Test == "" {
			continue
		}
		name := testName{
			pkg:  goOutput.Package,
			name: goOutput.Test,
		}
		if test, _, isSubtest := strings.Cut(goOutput.Test, "/"); isSubtest {
			name.name = test
			if goOutput.Action == "output" {
				resultMap[name].logs.WriteString(goOutput.Output)
			}
			continue
		}
		switch goOutput.Action {
		case "start":
			// ignore
		case "run":
			resultMap[name] = &testAttempt{
				name: name,
			}
		case "skip", "pass", "fail":
			resultMap[name].outcome = goOutput.Action
			out = append(out, resultMap[name])
		case "output":
			if strings.TrimSpace(goOutput.Output) == flakytest.FlakyTestLogMessage {
				resultMap[name].isMarkedFlaky = true
			} else {
				resultMap[name].logs.WriteString(goOutput.Output)
			}
		}
	}
	<-done
	return out
}

func main() {
	ctx := context.Background()

	// We only need to parse the -v flag to figure out whether to print the logs
	// for a test. We don't need to parse any other flags, so we just use the
	// flag package to parse the -v flag and then pass the rest of the args
	// through to 'go test'.
	// We run `go test -json` which returns the same information as `go test -v`,
	// but in a machine-readable format. So this flag is only for testwrapper's
	// output.
	v := flag.Bool("v", false, "verbose")

	flag.Usage = func() {
		fmt.Println("usage: testwrapper [testwrapper-flags] [pattern] [build/test flags & test binary flags]")
		fmt.Println()
		fmt.Println("testwrapper-flags:")
		flag.CommandLine.PrintDefaults()
		fmt.Println()
		fmt.Println("examples:")
		fmt.Println("\ttestwrapper -v ./... -count=1")
		fmt.Println("\ttestwrapper ./pkg/foo -run TestBar -count=1")
		fmt.Println()
		fmt.Println("Unlike 'go test', testwrapper requires a package pattern as the first positional argument and only supports a single pattern.")
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		fmt.Println("no pattern specified")
		flag.Usage()
		os.Exit(1)
	} else if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		fmt.Println("expected single pattern")
		flag.Usage()
		os.Exit(1)
	}
	pattern, otherArgs := args[0], args[1:]

	type nextRun struct {
		tests   []*packageTests
		attempt int
	}

	toRun := []*nextRun{
		{
			tests:   []*packageTests{{pattern: pattern}},
			attempt: 1,
		},
	}

	printPkgStatus := func(pkgName string, failed bool) {
		if failed {
			fmt.Println("FAIL\t", pkgName)
		} else {
			fmt.Println("ok\t", pkgName)
		}
	}

	for len(toRun) > 0 {
		var thisRun *nextRun
		thisRun, toRun = toRun[0], toRun[1:]

		if thisRun.attempt >= maxAttempts {
			fmt.Println("max attempts reached")
			os.Exit(1)
		}
		if thisRun.attempt > 1 {
			fmt.Printf("\n\nAttempt #%d: Retrying flaky tests:\n\n", thisRun.attempt)
		}

		failed := false
		toRetry := make(map[string][]string) // pkg -> tests to retry
		for _, pt := range thisRun.tests {
			output := runTests(ctx, thisRun.attempt, pt, otherArgs)
			slices.SortFunc(output, func(i, j *testAttempt) bool {
				if c := strings.Compare(i.name.pkg, j.name.pkg); c < 0 {
					return true
				} else if c > 0 {
					return false
				}
				return strings.Compare(i.name.name, j.name.name) <= 0
			})

			lastPkg := ""
			lastPkgFailed := false
			for _, tr := range output {
				if lastPkg == "" {
					lastPkg = tr.name.pkg
				} else if lastPkg != tr.name.pkg {
					printPkgStatus(lastPkg, lastPkgFailed)
					lastPkg = tr.name.pkg
					lastPkgFailed = false
				}
				if *v || tr.outcome == "fail" {
					io.Copy(os.Stdout, &tr.logs)
				}
				if tr.outcome != "fail" {
					continue
				}
				lastPkgFailed = true
				if tr.isMarkedFlaky {
					toRetry[tr.name.pkg] = append(toRetry[tr.name.pkg], tr.name.name)
				} else {
					failed = true
				}
			}
			printPkgStatus(lastPkg, lastPkgFailed)
		}
		if failed {
			fmt.Println("\n\nNot retrying flaky tests because non-flaky tests failed.")
			os.Exit(1)
		}
		if len(toRetry) == 0 {
			continue
		}
		pkgs := maps.Keys(toRetry)
		sort.Strings(pkgs)
		nextRun := &nextRun{
			attempt: thisRun.attempt + 1,
		}
		for _, pkg := range pkgs {
			tests := toRetry[pkg]
			sort.Strings(tests)
			nextRun.tests = append(nextRun.tests, &packageTests{
				pattern: pkg,
				tests:   tests,
			})
		}
		toRun = append(toRun, nextRun)
	}
}
