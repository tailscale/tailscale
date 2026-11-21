// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive && !ts_mac_gui

package cli

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tailscale/xnet/webdav"
	"golang.org/x/sys/unix"
)

func TestDriveGetQuarantine(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(&webdav.Handler{Prefix: "/example.com/pippo/shared", FileSystem: webdav.Dir(source), LockSystem: webdav.NewMemLS()})
	defer server.Close()
	destination, _, err := getDriveFile(context.Background(), driveTestStatus(), driveRemotePath{"pippo", "shared", "file"}, t.TempDir(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := unix.Getxattr(destination, "com.apple.quarantine", buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); !strings.HasPrefix(got, "0001;") || !strings.Contains(got, ";Tailscale;") {
		t.Fatalf("quarantine = %q", got)
	}
	assertNoDriveTemps(t, filepath.Dir(destination))
}
