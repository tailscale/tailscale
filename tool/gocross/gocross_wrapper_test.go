// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestGocrossWrapper(t *testing.T) {
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
