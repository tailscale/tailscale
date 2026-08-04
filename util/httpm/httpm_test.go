// Copyright (c) Tailscale Inc & contributors
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

	// Open the git index so Go's test cache tracks it as an input.
	// The index file changes on git reset, checkout, pull, etc.,
	// so the cache is properly invalidated when moving between commits.
	// Ask git for the path because .git is a file in a git worktree. Opening
	// only the index avoids recording the broader .git directory metadata.
	indexCmd := exec.Command("git", "rev-parse", "--path-format=absolute", "--git-path", "index")
	indexCmd.Dir = rootDir
	indexOut, err := indexCmd.Output()
	if err != nil {
		t.Skipf("skipping test since git index cannot be found: %v", err)
	}
	indexPath := strings.TrimSpace(string(indexOut))
	f, err := os.Open(indexPath)
	if err != nil {
		t.Fatalf("opening git index %q: %v", indexPath, err)
	}
	f.Close()

	cmd := exec.Command("git", "grep", "-l", "-F", "http.Method")
	cmd.Dir = rootDir
	matches, _ := cmd.Output()
	for fn := range strings.SplitSeq(strings.TrimSpace(string(matches)), "\n") {
		if strings.HasPrefix(fn, "tempfork/") {
			// Files under tempfork are vendored copies of upstream
			// code that we want to keep as close to upstream as
			// possible, so don't hold them to this rule.
			continue
		}
		switch fn {
		case "util/httpm/httpm.go", "util/httpm/httpm_test.go":
			continue
		}
		t.Errorf("http.MethodFoo constant used in %s; use httpm.FOO instead", fn)
	}
}
