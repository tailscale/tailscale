// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindModuleInfo(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, "tailscaled-version-test")
	out, err := exec.Command("go", "build", "-o", name, "tailscale.com/cmd/tailscaled").CombinedOutput()
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
