// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailscaleroot

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

// TestGoVersion tests that the Go version specified in go.mod matches ./tool/go version.
func TestGoVersion(t *testing.T) {
	// We could special-case ./tool/go path for Windows, but really there is no
	// need to run it there.
	if runtime.GOOS == "windows" {
		t.Skip("Skipping test on Windows")
	}
	goModVersion := mustGetGoModVersion(t)

	goToolCmd := exec.Command("./tool/go", "version")
	goToolOutput, err := goToolCmd.Output()
	if err != nil {
		t.Fatalf("Failed to get ./tool/go version: %v", err)
	}

	// Version info will approximately look like 'go version go1.24.4 linux/amd64'.
	parts := strings.Fields(string(goToolOutput))
	if len(parts) < 4 {
		t.Fatalf("Unexpected ./tool/go version output format: %s", goToolOutput)
	}

	goToolVersion := strings.TrimPrefix(parts[2], "go")

	if goModVersion != goToolVersion {
		t.Errorf("Go version in go.mod (%q) does not match the version of ./tool/go (%q).\nEnsure that the go.mod refers to the same Go version as ./go.toolchain.rev.",
			goModVersion, goToolVersion)
	}
}

func mustGetGoModVersion(t *testing.T) string {
	t.Helper()

	goModBytes, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}

	modFile, err := modfile.Parse("go.mod", goModBytes, nil)
	if err != nil {
		t.Fatal(err)
	}

	if modFile.Go == nil {
		t.Fatal("no Go version found in go.mod")
	}

	return modFile.Go.Version
}
