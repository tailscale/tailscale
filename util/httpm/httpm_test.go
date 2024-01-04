// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package httpm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUsedConsistently(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rootDir := filepath.Join(dir, "../..")

	// If we don't have a .git directory, we're not in a git checkout (e.g.
	// a downstream package); skip this test.
	if _, err := os.Stat(filepath.Join(rootDir, ".git")); err != nil {
		t.Skipf("skipping test since .git doesn't exist: %v", err)
	}

	cmd := exec.Command("git", "grep", "-l", "-F", "http.Method")
	cmd.Dir = rootDir
	matches, _ := cmd.Output()
	for _, fn := range strings.Split(strings.TrimSpace(string(matches)), "\n") {
		switch fn {
		case "util/httpm/httpm.go", "util/httpm/httpm_test.go":
			continue
		}
		t.Errorf("http.MethodFoo constant used in %s; use httpm.FOO instead", fn)
	}
}
