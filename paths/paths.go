// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package paths returns platform and user-specific default paths to
// Tailscale files and directories.
package paths

import (
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"tailscale.com/syncs"
	"tailscale.com/version/distro"
)

// AppSharedDir is a string set by the iOS or Android app on start
// containing a directory we can read/write in.
var AppSharedDir syncs.AtomicValue[string]

// WindowsProtectedPipePrefix is the prefix of the Windows named pipe names
// that only administrators may create. tailscaled's default socket is under
// it, which is what lets clients trust that whatever answers there is the
// Tailscale service (or an administrator's tailscaled) and not another user's.
const WindowsProtectedPipePrefix = `\\.\pipe\ProtectedPrefix\Administrators\`

// IsWindowsProtectedPipe reports whether path is a named pipe name under
// [WindowsProtectedPipePrefix]. Pipe names are case-insensitive.
func IsWindowsProtectedPipe(path string) bool {
	return len(path) > len(WindowsProtectedPipePrefix) &&
		strings.EqualFold(path[:len(WindowsProtectedPipePrefix)], WindowsProtectedPipePrefix)
}

// WindowsDevTailscaledSocket returns the named pipe that a tailscaled started
// by the current user with --windows-mode=dev listens on by default:
// \\.\pipe\tailscale-<username>. It returns "" on other platforms or if the
// current user is unknown.
func WindowsDevTailscaledSocket() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	u, err := user.Current()
	if err != nil {
		return ""
	}
	name := u.Username
	if _, after, ok := strings.Cut(name, `\`); ok {
		name = after // drop the MACHINE\ or DOMAIN\ prefix
	}
	return `\\.\pipe\tailscale-` + strings.ToLower(name)
}

// DefaultTailscaledSocket returns the path to the tailscaled Unix socket
// or the empty string if there's no reasonable default.
func DefaultTailscaledSocket() string {
	if runtime.GOOS == "windows" {
		return WindowsProtectedPipePrefix + `Tailscale\tailscaled`
	}
	if runtime.GOOS == "darwin" {
		return "/var/run/tailscaled.socket"
	}
	if runtime.GOOS == "plan9" {
		return "/srv/tailscaled.sock"
	}
	if runtime.GOOS == "android" {
		// Android (e.g. a userspace tailscaled under Termux) has no /var,
		// and the cwd-relative fallback below only works when the daemon
		// and the CLI happen to be started from the same directory
		// (see #21161). Use the shared per-app temp directory so both
		// agree on an absolute path.
		return filepath.Join(os.TempDir(), "tailscaled.sock")
	}
	switch distro.Get() {
	case distro.Synology:
		if distro.DSMVersion() == 6 {
			return "/var/packages/Tailscale/etc/tailscaled.sock"
		}
		// DSM 7 (and higher? or failure to detect.)
		return "/var/packages/Tailscale/var/tailscaled.sock"
	case distro.Gokrazy:
		return "/perm/tailscaled/tailscaled.sock"
	case distro.QNAP:
		return "/tmp/tailscale/tailscaled.sock"
	}
	if fi, err := os.Stat("/var/run"); err == nil && fi.IsDir() {
		return "/var/run/tailscale/tailscaled.sock"
	}
	return "tailscaled.sock"
}

// Overridden in init by OS-specific files.
var (
	stateFileFunc func() string

	// ensureStateDirPerms applies a restrictive ACL/chmod
	// to the provided directory.
	ensureStateDirPerms = func(string) error { return nil }
)

// DefaultTailscaledStateFile returns the default path to the
// tailscaled state file, or the empty string if there's no reasonable
// default value.
func DefaultTailscaledStateFile() string {
	if f := stateFileFunc; f != nil {
		return f()
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "Tailscale", "server-state.conf")
	}
	return ""
}

// DefaultTailscaledStateDir returns the default state directory
// to use for tailscaled, for use when the user provided neither
// a state directory or state file path to use.
//
// It returns the empty string if there's no reasonable default.
func DefaultTailscaledStateDir() string {
	if runtime.GOOS == "plan9" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("failed to get home directory: %v", err)
		}
		return filepath.Join(home, "tailscale-state")
	}
	return filepath.Dir(DefaultTailscaledStateFile())
}

// MakeAutomaticStateDir reports whether the platform
// automatically creates the state directory for tailscaled
// when it's absent.
func MakeAutomaticStateDir() bool {
	switch runtime.GOOS {
	case "plan9":
		return true
	case "linux":
		if distro.Get() == distro.JetKVM {
			return true
		}
	}
	return false
}

// MkStateDir ensures that dirPath, the daemon's configuration directory
// containing machine keys etc, both exists and has the correct permissions.
// We want it to only be accessible to the user the daemon is running under.
func MkStateDir(dirPath string) error {
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return err
	}
	return ensureStateDirPerms(dirPath)
}

// LegacyStateFilePath returns the legacy path to the state file when
// it was stored under the current user's %LocalAppData%.
//
// It is only called on Windows.
func LegacyStateFilePath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LocalAppData"), "Tailscale", "server-state.conf")
	}
	return ""
}
