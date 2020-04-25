// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package testenv is Tailscale's fork/subset of Go's
// internal/testenv. It exists to satisfy the tests of our fork of
// crypto/x509.
package testenv

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// HasGoBuild reports whether the current system can build programs with ``go build''
// and then run them with os.StartProcess or exec.Command.
func HasGoBuild() bool {
	if os.Getenv("GO_GCFLAGS") != "" {
		// It's too much work to require every caller of the go command
		// to pass along "-gcflags="+os.Getenv("GO_GCFLAGS").
		// For now, if $GO_GCFLAGS is set, report that we simply can't
		// run go build.
		return false
	}
	switch runtime.GOOS {
	case "android", "js":
		return false
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return false
		}
	}
	return true
}

// MustHaveGoBuild checks that the current system can build programs with ``go build''
// and then run them with os.StartProcess or exec.Command.
// If not, MustHaveGoBuild calls t.Skip with an explanation.
func MustHaveGoBuild(t testing.TB) {
	if os.Getenv("GO_GCFLAGS") != "" {
		t.Skipf("skipping test: 'go build' not compatible with setting $GO_GCFLAGS")
	}
	if !HasGoBuild() {
		t.Skipf("skipping test: 'go build' not available on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

// HasGoRun reports whether the current system can run programs with ``go run.''
func HasGoRun() bool {
	// For now, having go run and having go build are the same.
	return HasGoBuild()
}

// MustHaveGoRun checks that the current system can run programs with ``go run.''
// If not, MustHaveGoRun calls t.Skip with an explanation.
func MustHaveGoRun(t testing.TB) {
	if !HasGoRun() {
		t.Skipf("skipping test: 'go run' not available on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

// GoTool reports the path to the Go tool.
func GoTool() (string, error) {
	if !HasGoBuild() {
		return "", errors.New("platform cannot run go tool")
	}
	var exeSuffix string
	if runtime.GOOS == "windows" {
		exeSuffix = ".exe"
	}
	path := filepath.Join(runtime.GOROOT(), "bin", "go"+exeSuffix)
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}
	goBin, err := exec.LookPath("go" + exeSuffix)
	if err != nil {
		return "", errors.New("cannot find go tool: " + err.Error())
	}
	return goBin, nil
}

// GoToolPath reports the path to the Go tool.
// It is a convenience wrapper around GoTool.
// If the tool is unavailable GoToolPath calls t.Skip.
// If the tool should be available and isn't, GoToolPath calls t.Fatal.
func GoToolPath(t testing.TB) string {
	MustHaveGoBuild(t)
	path, err := GoTool()
	if err != nil {
		t.Fatal(err)
	}
	// Add all environment variables that affect the Go command to test metadata.
	// Cached test results will be invalidate when these variables change.
	// See golang.org/issue/32285.
	for _, envVar := range strings.Fields(KnownEnv) {
		os.Getenv(envVar)
	}
	return path
}

// KnownEnv is a list of environment variables that affect the operation
// of the Go command.
const KnownEnv = `
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
	GOARCH
	GOARM
	GOBIN
	GOCACHE
	GOENV
	GOEXE
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
	GOWASM
	GO_EXTLINK_ENABLED
	PKG_CONFIG
`
