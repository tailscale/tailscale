// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"flag"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFindModuleInfo(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "tailscaled-version-test")
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go"+exe())
	out, err := exec.Command(goTool, "build", "-o", name, "tailscale.com/cmd/tailscaled").CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build tailscaled: %v\n%s", err, out)
	}
	modinfo, err := findModuleInfo(name)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "path\ttailscale.com/cmd/tailscaled\nmod\ttailscale.com"
	if !strings.HasPrefix(modinfo, prefix) {
		t.Errorf("unexpected modinfo contents %q", modinfo)
	}
}

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

var findModuleInfoName = flag.String("module-info-file", "", "if non-empty, test findModuleInfo against this filename")

func TestFindModuleInfoManual(t *testing.T) {
	exe := *findModuleInfoName
	if exe == "" {
		t.Skip("skipping without --module-info-file filename")
	}
	cmd := cmdName(exe)
	mod, err := findModuleInfo(exe)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got %q from: %s", cmd, mod)
}
