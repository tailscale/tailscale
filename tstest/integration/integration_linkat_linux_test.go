// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTryLinkat(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	if err := os.WriteFile(src, []byte("hello world"), 0o755); err != nil {
		t.Fatal(err)
	}
	fd, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()

	dst := filepath.Join(t.TempDir(), "dst")
	if err := tryLinkat(fd, dst); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}

	var stSrc, stDst unix.Stat_t
	if err := unix.Stat(src, &stSrc); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(dst, &stDst); err != nil {
		t.Fatal(err)
	}
	if stSrc.Ino != stDst.Ino {
		t.Fatalf("inodes differ: src=%d, dst=%d", stSrc.Ino, stDst.Ino)
	}
}
