// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || freebsd || openbsd

package dns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvconfIsSystemdResolved(t *testing.T) {
	dir := t.TempDir()
	resolved := filepath.Join(dir, "resolvectl")
	if err := os.WriteFile(resolved, nil, 0755); err != nil {
		t.Fatal(err)
	}

	resolvconf := filepath.Join(dir, "resolvconf")
	if err := os.Symlink(resolved, resolvconf); err != nil {
		t.Fatal(err)
	}
	if !resolvconfIsSystemdResolved(resolvconf) {
		t.Fatal("resolvconf symlink to resolvectl was not recognized")
	}

	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, nil, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(resolvconf); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, resolvconf); err != nil {
		t.Fatal(err)
	}
	if resolvconfIsSystemdResolved(resolvconf) {
		t.Fatal("non-resolvectl symlink was incorrectly recognized")
	}

	if err := os.Remove(resolvconf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resolvconf, nil, 0755); err != nil {
		t.Fatal(err)
	}
	if resolvconfIsSystemdResolved(resolvconf) {
		t.Fatal("regular file was incorrectly recognized")
	}
}
