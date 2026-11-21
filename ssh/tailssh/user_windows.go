// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// GroupIds returns nil: on Windows the user's group memberships travel with
// the access token that the session process is created with, so tailssh
// never needs to enumerate them itself.
func (u *userMeta) GroupIds() ([]string, error) {
	return nil, nil
}

// isRootUser reports whether u is the Windows analog of root for the
// purposes of the "=" (autogroup:nonroot) SSH user mapping: the LocalSystem
// account or a built-in Administrator account (RID 500). Other members of the
// Administrators group are not considered root, as they are ordinary user
// accounts that happen to hold admin rights.
func isRootUser(u *userMeta) bool {
	sid, err := windows.StringToSid(u.Uid)
	if err != nil {
		return false
	}
	if sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	const domainAdminRID = 500
	n := sid.SubAuthorityCount()
	return n > 1 && sid.SubAuthority(uint32(n)-1) == domainAdminRID
}

// LoginShell returns the absolute path of the shell to run for SSH sessions.
// It is the same shell for every user: the OpenSSH for Windows DefaultShell
// registry value when set, else PowerShell 7 (pwsh.exe) if installed, else
// Windows PowerShell, else cmd.exe.
func (u *userMeta) LoginShell() string {
	return windowsLoginShell()
}

// openSSHRegKey is the registry key under HKEY_LOCAL_MACHINE where OpenSSH
// for Windows keeps its DefaultShell and DefaultShellCommandOption values.
// Honoring them lets Tailscale SSH sessions behave like sshd sessions on
// machines where an admin configured a shell.
const openSSHRegKey = `SOFTWARE\OpenSSH`

func openSSHRegValue(name string) string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, openSSHRegKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer key.Close()
	v, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

var windowsLoginShell = sync.OnceValue(func() string {
	if shell := openSSHRegValue("DefaultShell"); shell != "" && filepath.IsAbs(shell) {
		if p, err := exec.LookPath(shell); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("pwsh.exe"); err == nil {
		return p
	}
	if p, err := exec.LookPath(filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7", "pwsh.exe")); err == nil {
		return p
	}
	if p, err := exec.LookPath(filepath.Join(systemRoot(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")); err == nil {
		return p
	}
	return filepath.Join(systemRoot(), "System32", "cmd.exe")
})

func systemRoot() string {
	if v := os.Getenv("SystemRoot"); v != "" {
		return v
	}
	return `C:\Windows`
}

// shellCommandOption returns the flag that makes shell run a single command
// string given as the next argument: the OpenSSH for Windows
// DefaultShellCommandOption registry value when set, "/c" for cmd.exe, and
// "-c" for everything else. PowerShell and the common Unix-derived shells
// (bash, sh, zsh, fish) all accept "-c".
func shellCommandOption(shell string) string {
	if opt := openSSHRegValue("DefaultShellCommandOption"); opt != "" {
		return opt
	}
	if strings.EqualFold(filepath.Base(shell), "cmd.exe") {
		return "/c"
	}
	return "-c"
}

// windowsShellArgs returns the arguments to pass to shell to run rawCmd, or
// to start an interactive session if rawCmd is empty.
func windowsShellArgs(shell, rawCmd string) []string {
	if rawCmd == "" {
		return nil
	}
	return []string{shellCommandOption(shell), rawCmd}
}
