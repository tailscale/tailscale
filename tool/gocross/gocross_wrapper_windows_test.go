// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

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
		cmd := exec.Command("pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", ".\\gocross-wrapper.ps1", "version")
		cmd.Env = append(os.Environ(), "CI=true", "NOPWSHDEBUG=false", "TS_USE_GOCROSS=1") // for Set-PSDebug verbosity
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("gocross-wrapper.ps1 failed: %v\n%s", err, out)
		}
		if i > 0 && !strings.Contains(string(out), "$gocrossOk = $true\r\n") {
			t.Errorf("expected to find '$gocrossOk = $true'; got output:\n%s", out)
		}
	}
}
