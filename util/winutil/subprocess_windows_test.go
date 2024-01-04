// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// The code in this file is adapted from internal/testenv in the Go source tree
// and is used for writing tests that require spawning subprocesses.

var toRemove []string

func TestMain(m *testing.M) {
	status := m.Run()
	for _, file := range toRemove {
		os.RemoveAll(file)
	}
	os.Exit(status)
}

var testprog struct {
	sync.Mutex
	dir    string
	target map[string]*buildexe
}

type buildexe struct {
	once sync.Once
	exe  string
	err  error
}

func pathToTestProg(t *testing.T, binary string) string {
	exe, err := buildTestProg(t, binary, "-buildvcs=false")
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func startTestProg(t *testing.T, binary, name string, env ...string) {
	exe, err := buildTestProg(t, binary, "-buildvcs=false")
	if err != nil {
		t.Fatal(err)
	}

	startBuiltTestProg(t, exe, name, env...)
}

func startBuiltTestProg(t *testing.T, exe, name string, env ...string) {
	cmd := exec.Command(exe, name)
	cmd.Env = append(cmd.Env, env...)
	if testing.Short() {
		cmd.Env = append(cmd.Env, "RUNTIME_TEST_SHORT=1")
	}
	start(t, cmd)
}

var serializeBuild = make(chan bool, 2)

func buildTestProg(t *testing.T, binary string, flags ...string) (string, error) {
	testprog.Lock()
	if testprog.dir == "" {
		dir, err := os.MkdirTemp("", "go-build")
		if err != nil {
			t.Fatalf("failed to create temp directory: %v", err)
		}
		testprog.dir = dir
		toRemove = append(toRemove, dir)
	}

	if testprog.target == nil {
		testprog.target = make(map[string]*buildexe)
	}
	name := binary
	if len(flags) > 0 {
		nameFlags := make([]string, 0, len(flags))
		for _, flag := range flags {
			nameFlags = append(nameFlags, strings.ReplaceAll(flag, "=", "_"))
		}
		name += "_" + strings.Join(nameFlags, "_")
	}
	target, ok := testprog.target[name]
	if !ok {
		target = &buildexe{}
		testprog.target[name] = target
	}

	dir := testprog.dir

	// Unlock testprog while actually building, so that other
	// tests can look up executables that were already built.
	testprog.Unlock()

	target.once.Do(func() {
		// Only do two "go build"'s at a time,
		// to keep load from getting too high.
		serializeBuild <- true
		defer func() { <-serializeBuild }()

		// Don't get confused if goToolPath calls t.Skip.
		target.err = errors.New("building test called t.Skip")

		exe := filepath.Join(dir, name+".exe")

		t.Logf("running go build -o %s %s", exe, strings.Join(flags, " "))
		cmd := exec.Command(goToolPath(t), append([]string{"build", "-o", exe}, flags...)...)
		cmd.Dir = "testdata/" + binary
		out, err := cmd.CombinedOutput()
		if err != nil {
			target.err = fmt.Errorf("building %s %v: %v\n%s", binary, flags, err, out)
		} else {
			target.exe = exe
			target.err = nil
		}
	})

	return target.exe, target.err
}

// goTool reports the path to the Go tool.
func goTool() (string, error) {
	if !hasGoBuild() {
		return "", errors.New("platform cannot run go tool")
	}
	exeSuffix := ".exe"
	goroot, err := findGOROOT()
	if err != nil {
		return "", fmt.Errorf("cannot find go tool: %w", err)
	}
	path := filepath.Join(goroot, "bin", "go"+exeSuffix)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	goBin, err := exec.LookPath("go" + exeSuffix)
	if err != nil {
		return "", errors.New("cannot find go tool: " + err.Error())
	}
	return goBin, nil
}

// knownEnv is a list of environment variables that affect the operation
// of the Go command.
const knownEnv = `
	AR
	CC
	CGO_CFLAGS
	CGO_CFLAGS_ALLOW
	CGO_CFLAGS_DISALLOW
	CGO_CPPFLAGS
	CGO_CPPFLAGS_ALLOW
	CGO_CPPFLAGS_DISALLOW
	CGO_CXXFLAGS
	CGO_CXXFLAGS_ALLOW
	CGO_CXXFLAGS_DISALLOW
	CGO_ENABLED
	CGO_FFLAGS
	CGO_FFLAGS_ALLOW
	CGO_FFLAGS_DISALLOW
	CGO_LDFLAGS
	CGO_LDFLAGS_ALLOW
	CGO_LDFLAGS_DISALLOW
	CXX
	FC
	GCCGO
	GO111MODULE
	GO386
	GOAMD64
	GOARCH
	GOARM
	GOBIN
	GOCACHE
	GOENV
	GOEXE
	GOEXPERIMENT
	GOFLAGS
	GOGCCFLAGS
	GOHOSTARCH
	GOHOSTOS
	GOINSECURE
	GOMIPS
	GOMIPS64
	GOMODCACHE
	GONOPROXY
	GONOSUMDB
	GOOS
	GOPATH
	GOPPC64
	GOPRIVATE
	GOPROXY
	GOROOT
	GOSUMDB
	GOTMPDIR
	GOTOOLDIR
	GOVCS
	GOWASM
	GOWORK
	GO_EXTLINK_ENABLED
	PKG_CONFIG
`

// goToolPath reports the path to the Go tool.
// It is a convenience wrapper around goTool.
// If the tool is unavailable goToolPath calls t.Skip.
// If the tool should be available and isn't, goToolPath calls t.Fatal.
func goToolPath(t testing.TB) string {
	mustHaveGoBuild(t)
	path, err := goTool()
	if err != nil {
		t.Fatal(err)
	}
	// Add all environment variables that affect the Go command to test metadata.
	// Cached test results will be invalidate when these variables change.
	// See golang.org/issue/32285.
	for _, envVar := range strings.Fields(knownEnv) {
		os.Getenv(envVar)
	}
	return path
}

// hasGoBuild reports whether the current system can build programs with “go build”
// and then run them with os.StartProcess or exec.Command.
func hasGoBuild() bool {
	if os.Getenv("GO_GCFLAGS") != "" {
		// It's too much work to require every caller of the go command
		// to pass along "-gcflags="+os.Getenv("GO_GCFLAGS").
		// For now, if $GO_GCFLAGS is set, report that we simply can't
		// run go build.
		return false
	}
	return true
}

// mustHaveGoBuild checks that the current system can build programs with “go build”
// and then run them with os.StartProcess or exec.Command.
// If not, mustHaveGoBuild calls t.Skip with an explanation.
func mustHaveGoBuild(t testing.TB) {
	if os.Getenv("GO_GCFLAGS") != "" {
		t.Skipf("skipping test: 'go build' not compatible with setting $GO_GCFLAGS")
	}
	if !hasGoBuild() {
		t.Skipf("skipping test: 'go build' not available on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

var (
	gorootOnce sync.Once
	gorootPath string
	gorootErr  error
)

func findGOROOT() (string, error) {
	gorootOnce.Do(func() {
		gorootPath = runtime.GOROOT()
		if gorootPath != "" {
			// If runtime.GOROOT() is non-empty, assume that it is valid.
			//
			// (It might not be: for example, the user may have explicitly set GOROOT
			// to the wrong directory, or explicitly set GOROOT_FINAL but not GOROOT
			// and hasn't moved the tree to GOROOT_FINAL yet. But those cases are
			// rare, and if that happens the user can fix what they broke.)
			return
		}

		// runtime.GOROOT doesn't know where GOROOT is (perhaps because the test
		// binary was built with -trimpath, or perhaps because GOROOT_FINAL was set
		// without GOROOT and the tree hasn't been moved there yet).
		//
		// Since this is internal/testenv, we can cheat and assume that the caller
		// is a test of some package in a subdirectory of GOROOT/src. ('go test'
		// runs the test in the directory containing the packaged under test.) That
		// means that if we start walking up the tree, we should eventually find
		// GOROOT/src/go.mod, and we can report the parent directory of that.

		cwd, err := os.Getwd()
		if err != nil {
			gorootErr = fmt.Errorf("finding GOROOT: %w", err)
			return
		}

		dir := cwd
		for {
			parent := filepath.Dir(dir)
			if parent == dir {
				// dir is either "." or only a volume name.
				gorootErr = fmt.Errorf("failed to locate GOROOT/src in any parent directory")
				return
			}

			if base := filepath.Base(dir); base != "src" {
				dir = parent
				continue // dir cannot be GOROOT/src if it doesn't end in "src".
			}

			b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
			if err != nil {
				if os.IsNotExist(err) {
					dir = parent
					continue
				}
				gorootErr = fmt.Errorf("finding GOROOT: %w", err)
				return
			}
			goMod := string(b)

			for goMod != "" {
				var line string
				line, goMod, _ = strings.Cut(goMod, "\n")
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] == "module" && fields[1] == "std" {
					// Found "module std", which is the module declaration in GOROOT/src!
					gorootPath = parent
					return
				}
			}
		}
	})

	return gorootPath, gorootErr
}

// start runs cmd asynchronously and returns immediately.
func start(t testing.TB, cmd *exec.Cmd) {
	args := cmd.Args
	if args == nil {
		args = []string{cmd.Path}
	}

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", args, err)
	}
}
