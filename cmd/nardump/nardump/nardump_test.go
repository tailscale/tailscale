// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package nardump

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// setupTmpdir sets up a known golden layout, covering all allowed file/folder types in a nar.
func setupTmpdir(t *testing.T) string {
	t.Helper()
	tmpdir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(tmpdir, "sub/dir"), 0755))
	must(os.Symlink("brokenfile", filepath.Join(tmpdir, "brokenlink")))
	must(os.Symlink("sub/dir", filepath.Join(tmpdir, "dirl")))
	must(os.Symlink("/abs/nonexistentdir", filepath.Join(tmpdir, "dirb")))
	f, err := os.Create(filepath.Join(tmpdir, "sub/dir/file1"))
	must(err)
	f.Close()
	f, err = os.Create(filepath.Join(tmpdir, "file2m"))
	must(err)
	must(f.Truncate(2 * 1024 * 1024))
	f.Close()
	must(os.Symlink("../file2m", filepath.Join(tmpdir, "sub/goodlink")))
	return tmpdir
}

func TestWriteNAR(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Skip test on Windows as the Nix package manager is not supported on this platform
		t.Skip("nix package manager is not available on Windows")
	}
	dir := setupTmpdir(t)
	// obtained via `nix-store --dump /tmp/... | sha256sum` of the above test dir
	const expected = "727613a36f41030e93a4abf2649c3ec64a2757ccff364e3f6f7d544eb976e442"
	h := sha256.New()
	if err := WriteNAR(h, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", h.Sum(nil)); got != expected {
		t.Fatalf("sha256sum of nar: got %s, want %s", got, expected)
	}
}
