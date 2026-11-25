// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package upki

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func setCacheDirsForTest(t *testing.T, dirs ...string) {
	old := cacheDirs
	cacheDirs = func() []string { return dirs }
	t.Cleanup(func() { cacheDirs = old })
}

func TestFindCacheDir(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "missing")
	empty := filepath.Join(tmp, "empty") // created but never fetched into
	populated := filepath.Join(tmp, "populated")
	for _, d := range []string{empty, populated} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(populated, indexFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	setCacheDirsForTest(t, missing, empty)
	if got := findCacheDir(); got != "" {
		t.Errorf("findCacheDir with no index = %q; want empty", got)
	}

	setCacheDirsForTest(t, missing, empty, populated)
	if got := findCacheDir(); got != populated {
		t.Errorf("findCacheDir = %q; want %q", got, populated)
	}
}

func TestCheckRevocationFailsOpen(t *testing.T) {
	// The certificates are never parsed when there's no usable cache, so
	// empty ones suffice.
	chain := []*x509.Certificate{{}, {}}

	setCacheDirsForTest(t, filepath.Join(t.TempDir(), "missing"))
	if err := checkRevocation("example.com", chain); err != nil {
		t.Errorf("no cache: got %v; want nil", err)
	}

	corrupt := t.TempDir()
	if err := os.WriteFile(filepath.Join(corrupt, indexFile), []byte("not an index"), 0o644); err != nil {
		t.Fatal(err)
	}
	setCacheDirsForTest(t, corrupt)
	if err := checkRevocation("example.com", chain); err != nil {
		t.Errorf("corrupt index: got %v; want nil", err)
	}
}
