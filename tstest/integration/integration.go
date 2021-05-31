// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package integration contains Tailscale integration tests.
//
// This package is considered internal and the public API is subject
// to change without notice.
package integration

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/version"
)

// Binaries are the paths to a tailscaled and tailscale binary.
// These can be shared by multiple nodes.
type Binaries struct {
	Dir    string // temp dir for tailscale & tailscaled
	Daemon string // tailscaled
	CLI    string // tailscale
}

// BuildTestBinaries builds tailscale and tailscaled, failing the test
// if they fail to compile.
func BuildTestBinaries(t testing.TB) *Binaries {
	td := t.TempDir()
	build(t, td, "tailscale.com/cmd/tailscaled", "tailscale.com/cmd/tailscale")
	return &Binaries{
		Dir:    td,
		Daemon: filepath.Join(td, "tailscaled"+exe()),
		CLI:    filepath.Join(td, "tailscale"+exe()),
	}
}

// buildMu limits our use of "go build" to one at a time, so we don't
// fight Go's built-in caching trying to do the same build concurrently.
var buildMu sync.Mutex

func build(t testing.TB, outDir string, targets ...string) {
	buildMu.Lock()
	defer buildMu.Unlock()

	t0 := time.Now()
	defer func() { t.Logf("built %s in %v", targets, time.Since(t0).Round(time.Millisecond)) }()

	goBin := findGo(t)
	cmd := exec.Command(goBin, "install")
	if version.IsRace() {
		cmd.Args = append(cmd.Args, "-race")
	}
	cmd.Args = append(cmd.Args, targets...)
	cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH, "GOBIN="+outDir)
	errOut, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	if strings.Contains(string(errOut), "when GOBIN is set") {
		// Fallback slow path for cross-compiled binaries.
		for _, target := range targets {
			outFile := filepath.Join(outDir, path.Base(target)+exe())
			cmd := exec.Command(goBin, "build", "-o", outFile, target)
			cmd.Env = append(os.Environ(), "GOARCH="+runtime.GOARCH)
			if errOut, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("failed to build %v with %v: %v, %s", target, goBin, err, errOut)
			}
		}
		return
	}
	t.Fatalf("failed to build %v with %v: %v, %s", targets, goBin, err, errOut)
}

func findGo(t testing.TB) string {
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go"+exe())
	if fi, err := os.Stat(goBin); err != nil {
		if os.IsNotExist(err) {
			t.Fatalf("failed to find go at %v", goBin)
		}
		t.Fatalf("looking for go binary: %v", err)
	} else if !fi.Mode().IsRegular() {
		t.Fatalf("%v is unexpected %v", goBin, fi.Mode())
	}
	return goBin
}

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
