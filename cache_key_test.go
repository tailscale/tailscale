// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailscaleroot

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"tailscale.com/util/cibuild"
)

// TestTsgoRevInCacheKey verifies that the Tailscale Go toolchain's git
// revision (from go.toolchain.rev) is blended into Go build cache keys.
// Without this, bumping the toolchain to a new commit that doesn't change
// the Go version number would silently reuse stale cached build artifacts.
//
// See https://github.com/tailscale/tailscale/issues/36589.
func TestTsgoRevInCacheKey(t *testing.T) {
	goRoot := goEnv(t, "GOROOT")
	isTsgo := strings.Contains(goRoot, "/.cache/tsgo/")
	if !cibuild.On() && !isTsgo {
		t.Skip("skipping; not in CI and not using the Tailscale Go toolchain")
	}

	rev := strings.TrimSpace(GoToolchainRev)
	if rev == "" {
		t.Fatal("go.toolchain.rev is empty")
	}

	// Build the small stdlib "errors" package with GODEBUG=gocachehash=1,
	// which causes cmd/go to log its cache key computations to stderr.
	cmd := exec.Command("go", "build", "errors")
	cmd.Env = append(os.Environ(), "GODEBUG=gocachehash=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build errors failed: %v\n%s", err, out)
	}

	// The cache key output should contain the toolchain rev alongside the
	// Go version, e.g.:
	//   HASH[moduleIndex]: "go1.26.2 dfe2a5fd8ee2e68b08ce5ff259269f50ecadf2f4"
	if !strings.Contains(string(out), rev) {
		t.Errorf("go.toolchain.rev %q not found in GODEBUG=gocachehash=1 output:\n%s", rev, out)
	}
}

func goEnv(t *testing.T, key string) string {
	t.Helper()
	out, err := exec.Command("go", "env", key).Output()
	if err != nil {
		t.Fatalf("go env %s: %v", key, err)
	}
	return strings.TrimSpace(string(out))
}
