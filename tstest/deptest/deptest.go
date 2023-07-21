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
	"runtime"
	"testing"
)

type DepChecker struct {
	GOOS    string
	GOARCH  string
	BadDeps map[string]string // package => why
}

func (c DepChecker) Check(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Slow and avoid caring about "go.exe" etc.
		t.Skip("skipping dep tests on windows hosts")
	}
	t.Helper()
	cmd := exec.Command("go", "list", "-json", ".")
	var extraEnv []string
	if c.GOOS != "" {
		extraEnv = append(extraEnv, "GOOS="+c.GOOS)
	}
	if c.GOARCH != "" {
		extraEnv = append(extraEnv, "GOARCH="+c.GOARCH)
	}
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Deps []string
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}

	for _, dep := range res.Deps {
		if why, ok := c.BadDeps[dep]; ok {
			t.Errorf("package %q is not allowed as a dependency (env: %q); reason: %s", dep, extraEnv, why)
		}
	}
	t.Logf("got %d dependencies", len(res.Deps))

}
