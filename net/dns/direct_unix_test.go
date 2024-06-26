// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package dns

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteFileUmask(t *testing.T) {
	// Set a umask that disallows world-readable files for the duration of
	// this test.
	oldUmask := syscall.Umask(0027)
	defer syscall.Umask(oldUmask)

	tmp := t.TempDir()
	fs := directFS{prefix: tmp}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := directManager{logf: t.Logf, fs: fs, ctx: ctx, ctxClose: cancel}

	const perms = 0644
	if err := m.atomicWriteFile(fs, "resolv.conf", []byte("nameserver 8.8.8.8\n"), perms); err != nil {
		t.Fatal(err)
	}

	// Ensure that the created file has the world-readable bit set.
	fi, err := os.Stat(filepath.Join(tmp, "resolv.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != perms {
		t.Fatalf("file mode: got 0o%o, want 0o%o", got, perms)
	}
}
