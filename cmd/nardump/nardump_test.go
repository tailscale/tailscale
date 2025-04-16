// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"testing"
)

// setupTmpdir sets up a known golden layout, covering all allowed file/folder types in a nar
func setupTmpdir(t *testing.T) string {
	tmpdir := t.TempDir()
	pwd, _ := os.Getwd()
	os.Chdir(tmpdir)
	defer os.Chdir(pwd)
	os.MkdirAll("sub/dir", 0755)
	os.Symlink("brokenfile", "brokenlink")
	os.Symlink("sub/dir", "dirl")
	os.Symlink("/abs/nonexistentdir", "dirb")
	os.Create("sub/dir/file1")
	f, _ := os.Create("file2m")
	_ = f.Truncate(2 * 1024 * 1024)
	f.Close()
	os.Symlink("../file2m", "sub/goodlink")
	return tmpdir
}

func TestWriteNar(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Skip test on Windows as the Nix package manager is not supported on this platform
		t.Skip("nix package manager is not available on Windows")
	}
	dir := setupTmpdir(t)
	t.Run("nar", func(t *testing.T) {
		// obtained via `nix-store --dump /tmp/... | sha256sum` of the above test dir
		expected := "727613a36f41030e93a4abf2649c3ec64a2757ccff364e3f6f7d544eb976e442"
		h := sha256.New()
		os.Chdir(dir)
		err := writeNAR(h, os.DirFS("."))
		if err != nil {
			t.Fatal(err)
		}
		hash := fmt.Sprintf("%x", h.Sum(nil))
		if expected != hash {
			t.Fatal("sha256sum of nar not matched", hash, expected)
		}
	})
}
