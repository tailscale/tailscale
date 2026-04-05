// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package main

import (
	"bytes"
	"go/version"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/util/must"
)

func TestGocrossWrapper(t *testing.T) {
	if version.Compare(runtime.Version(), "go1.27") < 0 {
		gitDir := must.Get(exec.Command("git", "rev-parse", "--git-dir").Output())
		gitCommonDir := must.Get(exec.Command("git", "rev-parse", "--git-common-dir").Output())
		if !bytes.Equal(gitDir, gitCommonDir) {
			t.Skip("skipping within git worktree, see https://go.dev/issue/58218")
		}
	}

	for i := range 2 { // once to build gocross; second to test it's cached
		cmd := exec.Command("./gocross-wrapper.sh", "version")
		cmd.Env = append(os.Environ(), "CI=true", "NOBASHDEBUG=false", "TS_USE_GOCROSS=1") // for "set -x" verbosity
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("gocross-wrapper.sh failed: %v\n%s", err, out)
		}
		if i > 0 && !strings.Contains(string(out), "gocross_ok=1\n") {
			t.Errorf("expected to find 'gocross_ok=1'; got output:\n%s", out)
		}
	}
}
