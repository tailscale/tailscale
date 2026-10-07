// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//go:build !android

package taildrop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFSRenameInvalidName(t *testing.T) {
	for _, name := range []string{
		"", ".", "..", "../outside", "sub/file", `sub\file`,
		"/absolute", `C:\absolute`, "file:stream", " file", "file ",
		"file\x00", "\xff", strings.Repeat("a", 256),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			// An absent source ensures validation precedes filesystem access.
			got, err := (fsFileOps{rootDir: dir}).Rename(filepath.Join(dir, "missing.partial"), name)
			if !errors.Is(err, ErrInvalidFileName) || got != "" {
				t.Fatalf("Rename(_, %q) = %q, %v; want empty path, ErrInvalidFileName", name, got, err)
			}
		})
	}
}

func TestFSRename(t *testing.T) {
	for _, tt := range []struct {
		name     string
		existing string
		wantName string
	}{
		{"new", "", "file.txt"},
		{"duplicate", "incoming", "file.txt"},
		{"collision", "different", "file (1).txt"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			src := filepath.Join(dir, "file.txt.partial")
			if err := os.WriteFile(src, []byte("incoming"), 0600); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "file.txt")
			if tt.existing != "" {
				if err := os.WriteFile(dst, []byte(tt.existing), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := (fsFileOps{rootDir: dir}).Rename(src, "file.txt")
			if err != nil || got != filepath.Join(dir, tt.wantName) {
				t.Fatalf("Rename = %q, %v; want %q, nil", got, err, filepath.Join(dir, tt.wantName))
			}
			if data, err := os.ReadFile(got); err != nil || string(data) != "incoming" {
				t.Fatalf("destination contents = %q, %v; want incoming", data, err)
			}
			if _, err := os.Stat(src); !os.IsNotExist(err) {
				t.Fatalf("source still exists: %v", err)
			}
			if tt.name == "collision" {
				if data, err := os.ReadFile(dst); err != nil || string(data) != tt.existing {
					t.Fatalf("existing file contents = %q, %v; want %q", data, err, tt.existing)
				}
			}
		})
	}
}
