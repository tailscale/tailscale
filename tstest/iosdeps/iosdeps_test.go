// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// No need to run this on Windows where CI's slow enough. Then we don't need to
// worry about "go.exe" etc.

//go:build !windows

package iosdeps

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestDeps(t *testing.T) {
	cmd := exec.Command("go", "list", "-json", ".")
	cmd.Env = append(os.Environ(), "GOOS=ios", "GOARCH=arm64")
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
		switch dep {
		case "text/template", "html/template":
			t.Errorf("package %q is not allowed as a dependency on iOS", dep)
		}
	}
	t.Logf("got %d dependencies", len(res.Deps))
}
