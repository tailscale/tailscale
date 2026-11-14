// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	gliderssh "github.com/tailscale/gliderssh"
	"golang.org/x/sys/windows"
)

func TestIsRootUser(t *testing.T) {
	tests := []struct {
		sid  string
		want bool
	}{
		{"S-1-5-18", true}, // LocalSystem
		{"S-1-5-21-1801390406-3229670570-2477332089-500", true},  // built-in Administrator
		{"S-1-5-21-1801390406-3229670570-2477332089-501", false}, // Guest
		{"S-1-5-21-1801390406-3229670570-2477332089-1001", false},
		{"S-1-5-32-544", false}, // the Administrators group itself
		{"not-a-sid", false},
	}
	for _, tt := range tests {
		u := &userMeta{User: user.User{Uid: tt.sid}}
		if got := isRootUser(u); got != tt.want {
			t.Errorf("isRootUser(%q) = %v; want %v", tt.sid, got, tt.want)
		}
	}
}

func TestWindowsShellArgs(t *testing.T) {
	if openSSHRegValue("DefaultShellCommandOption") != "" {
		t.Skip("OpenSSH DefaultShellCommandOption is configured on this machine")
	}
	tests := []struct {
		shell, cmd string
		want       []string
	}{
		{`C:\Windows\System32\cmd.exe`, "", nil},
		{`C:\Windows\System32\cmd.exe`, "dir", []string{"/c", "dir"}},
		{`C:\Windows\System32\CMD.EXE`, "dir", []string{"/c", "dir"}},
		{`C:\Program Files\PowerShell\7\pwsh.exe`, "", nil},
		{`C:\Program Files\PowerShell\7\pwsh.exe`, "Get-Location", []string{"-c", "Get-Location"}},
		{`C:\Program Files\Git\bin\bash.exe`, "ls -l", []string{"-c", "ls -l"}},
	}
	for _, tt := range tests {
		if got := windowsShellArgs(tt.shell, tt.cmd); !slices.Equal(got, tt.want) {
			t.Errorf("windowsShellArgs(%q, %q) = %q; want %q", tt.shell, tt.cmd, got, tt.want)
		}
	}
}

func TestWindowsLoginShell(t *testing.T) {
	shell := (&userMeta{}).LoginShell()
	if !filepath.IsAbs(shell) {
		t.Fatalf("LoginShell = %q; want an absolute path", shell)
	}
	base := strings.ToLower(filepath.Base(shell))
	t.Logf("login shell: %v", shell)
	if openSSHRegValue("DefaultShell") == "" && base != "pwsh.exe" && base != "powershell.exe" && base != "cmd.exe" {
		t.Errorf("unexpected default shell %q", shell)
	}
}

func TestPtySize(t *testing.T) {
	tests := []struct {
		w    gliderssh.Window
		want windows.Coord
	}{
		{gliderssh.Window{Width: 120, Height: 40}, windows.Coord{X: 120, Y: 40}},
		{gliderssh.Window{}, windows.Coord{X: 80, Y: 24}},
		{gliderssh.Window{Width: -1, Height: 1 << 20}, windows.Coord{X: 80, Y: 24}},
	}
	for _, tt := range tests {
		if got := ptySize(tt.w); got != tt.want {
			t.Errorf("ptySize(%+v) = %+v; want %+v", tt.w, got, tt.want)
		}
	}
}

func TestWindowsLocalUsernames(t *testing.T) {
	names, err := windowsLocalUsernames()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("local users: %q", names)
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	_, name, _ := strings.Cut(u.Username, `\`)
	if strings.EqualFold(name, "SYSTEM") || strings.HasSuffix(name, "$") {
		t.Skipf("running as %q, not a local user account", u.Username)
	}
	if !slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, name) }) {
		t.Errorf("current user %q not in local user list %q", name, names)
	}
}
