package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/util/mak"
)

func main() {
	log.SetFlags(log.Lshortfile)
	log.SetPrefix("testwrapper: ")

	// Build go args: test [-work] ...
	var workdir string
	var args = []string{"test"}
	if !slices.Contains(args, "-work") && !slices.Contains(args, "--work") {
		args = append(args, "-work")
		defer func() {
			if workdir != "" {
				// Clean up the WORK directory as the user didn't want it.
				if err := os.RemoveAll(workdir); err != nil {
					log.Printf("error removing workdir: %s", err)
				}
			}
		}()
	}
	args = append(args, os.Args[1:]...)

	// Run go test.
	attempt := 1
	r, xerr := run("go", args, []string{attemptenv(attempt)}, os.Stdout, os.Stderr)
	if nonexecerr(xerr) {
		log.Fatal("go test: ", xerr)
	}

	// Check whether anything needs retried.
	log.Printf("failures: builds=%d tests=%d retryable=%d", r.buildFailures, r.testFailures, r.testFailuresRetryable)
	if r.buildFailures > 0 || r.testFailuresRetryable == 0 || r.testFailures > r.testFailuresRetryable {
		exit(xerr)
	}

	// Retry tests we found.
	const maxAttempts = 3
	for cmd := range r.retryCmds {
		pkg := strings.TrimSuffix(cmdPkg(cmd), ".test")
		for {
			attempt++
			p := r.retryCmds[cmd]
			log.Printf("attempt %d: %s %s", attempt, pkg, strings.Join(p.tests, " "))

			// Retry the test by invoking the built pkg.test binary directly.
			pr, xerr := run(
				cmd,
				append(p.args, "-test.run=^"+strings.Join(p.tests, "$|^")+"$"),
				[]string{attemptenv(attempt)},
				os.Stdout, os.Stdout, // go test copies all underlying pkg.test output to stdout
			)
			if nonexecerr(xerr) {
				log.Fatalf("%s: %s", cmd, xerr)
			}
			if code, _ := exitcode(xerr); code == 0 {
				break // all tests passed.
			}

			if attempt == maxAttempts {
				log.Fatalf("failed %d times: %s %s", attempt, pkg, strings.Join(p.tests, " "))
			}

			// Try again with the new failure instructions. Hopefully with fewer
			// failed tests...
			r.retryCmds[cmd] = pr.retryCmds[cmd]
		}
	}
}

// attemptenv returns the environment variable value K=V used to signal
// [flakytest] that it's in a test environment.
func attemptenv(attempt int) string {
	return flakytest.FlakeAttemptEnv + "=" + strconv.Itoa(attempt)
}

type testRun struct {
	workDir string

	buildFailures         int
	testFailures          int
	testFailuresRetryable int

	retryCmds map[string]pkgRetry // cmd path => retry instructions
}

type pkgRetry struct {
	cmd   string
	args  []string
	tests []string
}

// run executes prog with args and environ, writing output to stdout and stderr
// and returns the error from [exec.Cmd.Wait], along with information parsed
// from the output about how many builds or tests failed and how to retry them.
func run(prog string, args []string, environ []string, stdout, stderr io.Writer) (r testRun, _ error) {
	cmd := exec.Command(prog, args...)
	cmd.Env = append(os.Environ(), environ...)
	cmdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("StdoutPipe: %s", err)
	}
	cmderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatalf("StderrPipe: %s", err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatalf("Start: %s", err)
	}

	var wg sync.WaitGroup

	// Read WORK= from first line of stderr. We retain this so we can clean it
	// when testwrapper ends.
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := readthrulines(cmderr, stderr, func(line string) {
			if r.workDir == "" {
				if w, ok := strings.CutPrefix(line, "WORK="); ok {
					r.workDir = w
				}
			}
		})
		if err != nil {
			log.Fatalf("reading stderr: %s", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := readthrulines(cmdout, stdout, func(line string) {
			if strings.HasPrefix(line, "--- FAIL: Test") {
				r.testFailures++
				return
			}
			if strings.HasPrefix(line, "FAIL\t") && strings.HasSuffix(line, "[build failed]") {
				r.buildFailures++
				return
			}
			if _, args, ok := strings.Cut(line, "flakytest: retry:"); ok {
				wargs := strings.Split(strings.TrimSpace(args), " ")
				if len(wargs) < 2 {
					log.Printf("failed to retry log line %q", line)
					return
				}
				test, cmd, args := wargs[0], wargs[1], wargs[2:]

				p := r.retryCmds[cmd]
				p.cmd = cmd
				p.args = args
				p.tests = append(p.tests, test)
				mak.Set(&r.retryCmds, cmd, p)
				r.testFailuresRetryable++
				return
			}
		})
		if err != nil {
			log.Fatalf("reading stdout: %s", err)
		}
	}()

	wg.Wait()
	xerr := cmd.Wait()
	return r, xerr
}

// exit calls os.Exit with the exit code for err.
func exit(err error) {
	code, _ := exitcode(err)
	os.Exit(code)
}

// nonexecerr reports whether err is an error which prevented a program executing.
func nonexecerr(err error) bool {
	if err == nil {
		return false
	}
	xe := &exec.ExitError{}
	return !errors.As(err, &xe) || xe.ExitCode() < 0
}

// exitcode returns a representative error code for err. If err has an
// ExitCode() int method, its exit code is returned.
func exitcode(err error) (code int, ok bool) {
	if xe := (interface{ ExitCode() int })(nil); errors.As(err, &xe) {
		return xe.ExitCode(), true
	}
	if err != nil {
		return 1, false
	}
	return 0, false
}

// readthrulines copies r to w, calling f with each line of text.
func readthrulines(r io.Reader, w io.Writer, f func(line string)) error {
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		f(line)
		io.WriteString(w, line)
		io.WriteString(w, "\n")
	}
	return s.Err()
}

// cmdPkg will return the package of the binary that was built. From Go 1.24 on,
// this will return the full package path followed by the ".test" from the
// autogenerated main test pkg. For earlier Go versions return base(exe).
func cmdPkg(exe string) string {
	v, _ := exec.Command("go", "version", "-m", exe).Output()
	_, vp, ok := bytes.Cut(v, []byte("\n\tpath\t"))
	if ok {
		p, _, _ := bytes.Cut(vp, []byte("\n"))
		p = bytes.TrimSpace(p)
		if len(p) > 0 {
			return string(p)
		}
	}
	return filepath.Base(exe)
}
