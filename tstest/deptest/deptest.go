// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The deptest package contains a shared implementation of negative
// dependency tests for other packages, making sure we don't start
// depending on certain packages.
package deptest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"tailscale.com/util/set"
)

type DepChecker struct {
	GOOS     string            // optional
	GOARCH   string            // optional
	OnDep    func(string)      // if non-nil, called per dependency
	OnImport func(string)      // if non-nil, called per import
	BadDeps  map[string]string // package => why
	WantDeps set.Set[string]   // packages expected
	Tags     string            // comma-separated
	ExtraEnv []string          // extra environment for "go list" (e.g. CGO_ENABLED=1)
}

func (c DepChecker) Check(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Slow and avoid caring about "go.exe" etc.
		t.Skip("skipping dep tests on windows hosts")
	}
	t.Helper()
	cmd := exec.Command("go", "list", "-json", "-tags="+c.Tags, ".")
	var extraEnv []string
	if c.GOOS != "" {
		extraEnv = append(extraEnv, "GOOS="+c.GOOS)
	}
	if c.GOARCH != "" {
		extraEnv = append(extraEnv, "GOARCH="+c.GOARCH)
	}
	extraEnv = append(extraEnv, c.ExtraEnv...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Imports []string
		Deps    []string
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}

	tsRoot := sync.OnceValue(func() string {
		out, err := exec.Command("go", "list", "-f", "{{.Dir}}", "tailscale.com").Output()
		if err != nil {
			t.Fatalf("failed to find tailscale.com root: %v", err)
		}
		return strings.TrimSpace(string(out))
	})

	if c.OnImport != nil {
		for _, imp := range res.Imports {
			c.OnImport(imp)
		}
	}

	for _, dep := range res.Deps {
		if c.OnDep != nil {
			c.OnDep(dep)
		}
		if why, ok := c.BadDeps[dep]; ok {
			t.Errorf("package %q is not allowed as a dependency (env: %q); reason: %s", dep, extraEnv, why)
		}
	}
	// Make sure the BadDeps packages actually exists. If they got renamed or
	// moved around, we should update the test referencing the old name.
	// Doing this in the general case requires network access at runtime
	// (resolving a package path to its module, possibly doing the ?go-get=1
	// meta tag dance), so we just check the common case of
	// "tailscale.com/*" packages for now, with the assumption that all
	// "tailscale.com/*" packages are in the same module, which isn't
	// necessarily true in the general case.
	for dep := range c.BadDeps {
		if suf, ok := strings.CutPrefix(dep, "tailscale.com/"); ok {
			pkgDir := filepath.Join(tsRoot(), suf)
			if _, err := os.Stat(pkgDir); err != nil {
				t.Errorf("listed BadDep %q doesn't seem to exist anymore: %v", dep, err)
			}
		}
	}
	for dep := range c.WantDeps {
		if !slices.Contains(res.Deps, dep) {
			t.Errorf("expected package %q to be a dependency (env: %q)", dep, extraEnv)
		}
	}
	t.Logf("got %d dependencies", len(res.Deps))
}

// ImportAliasCheck checks that all packages are imported according to Tailscale
// conventions.
func ImportAliasCheck(t testing.TB, relDir string) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(dir, relDir)

	cmd := exec.Command("git", "grep", "-n", "-F", `"golang.org/x/exp/`)
	cmd.Dir = dir
	matches, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("ignoring error: %v, %s", err, matches)
		return
	}
	badRx := regexp.MustCompile(`^([^:]+:\d+):\s+"golang\.org/x/exp/(slices|maps)"`)
	if s := strings.TrimSpace(string(matches)); s != "" {
		for _, line := range strings.Split(s, "\n") {
			if m := badRx.FindStringSubmatch(line); m != nil {
				t.Errorf("%s: the x/exp/%s package should be imported as x%s", m[1], m[2], m[2])
			}
		}
	}
}
