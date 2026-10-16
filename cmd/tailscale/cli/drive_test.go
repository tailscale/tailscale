// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive && !ts_mac_gui

package cli

import (
	"context"
	"strings"
	"testing"
)

func TestParseDriveRemotePath(t *testing.T) {
	tests := []struct {
		arg  string
		want driveRemotePath
	}{
		{"pippo:shared", driveRemotePath{"pippo", "shared", ""}},
		{"pippo:shared/", driveRemotePath{"pippo", "shared", ""}},
		{"pippo:shared/path/to/directory", driveRemotePath{"pippo", "shared", "path/to/directory"}},
		{"pippo:shared/subdirectory/", driveRemotePath{"pippo", "shared", "subdirectory/"}},
		{"pippo.example.ts.net:shared", driveRemotePath{"pippo.example.ts.net", "shared", ""}},
		{"100.101.102.103:shared", driveRemotePath{"100.101.102.103", "shared", ""}},
		{"pippo:my share/My Documents", driveRemotePath{"pippo", "my share", "My Documents"}},
		{"pippo:shared/a:b/%2e%2e/#?", driveRemotePath{"pippo", "shared", "a:b/%2e%2e/#?"}},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			got, err := parseDriveRemotePath(tt.arg)
			if err != nil || got != tt.want {
				t.Fatalf("parseDriveRemotePath(%q) = %+v, %v; want %+v, nil", tt.arg, got, err, tt.want)
			}
		})
	}
}

func TestParseDriveRemotePathInvalid(t *testing.T) {
	for _, arg := range []string{
		"", "pippo", ":shared", "pippo:", "pippo:/directory", "pippo: ",
		"pippo/shared:directory", "pip po:shared", "pippo\n:shared",
		"pippo:.", "pippo:..", "pippo:shared/..", "pippo:shared/a/../b",
		"pippo::shared", "[fd7a:115c:a1e0::1]:shared", "fd7a:115c:a1e0::1:shared",
		"pippo:shared/a\x00b", `pippo\other:shared`, `pippo:shared\other`,
	} {
		t.Run(arg, func(t *testing.T) {
			if got, err := parseDriveRemotePath(arg); err == nil {
				t.Fatalf("parseDriveRemotePath(%q) = %+v, nil; want error", arg, got)
			}
		})
	}
}

func TestDriveLs(t *testing.T) {
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"ls"}, "usage: " + driveLsUsage},
		{[]string{"ls", "pippo:shared", "extra"}, "usage: " + driveLsUsage},
		{[]string{"ls", "pippo"}, "invalid remote path"},
	} {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			cmd := driveCmd()
			if err := cmd.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Run(context.Background()); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Run() error = %v; want error containing %q", err, tt.want)
			}
		})
	}
}
