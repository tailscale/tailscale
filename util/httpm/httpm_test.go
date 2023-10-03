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
	cmd := exec.Command("git", "grep", "-l", "-F", "http.Method")
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Dir = filepath.Join(dir, "../..")
	matches, _ := cmd.Output()
	for _, fn := range strings.Split(strings.TrimSpace(string(matches)), "\n") {
		switch fn {
		case "util/httpm/httpm.go", "util/httpm/httpm_test.go":
			continue
		}
		t.Errorf("http.MethodFoo constant used in %s; use httpm.FOO instead", fn)
	}
}
