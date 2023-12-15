//go:build unix

package tailfs

import "tailscale.com/version"

func useUserServers() bool {
	// All UNIX platforms use user servers (sub-processes) to access the OS
	// filesystem as a specific unprivileged users, except for sandboxed macOS
	// which doesn't support impersonating users and instead accesses files
	// through the macOS GUI app as whatever unprivileged user is running it.
	return !version.IsSandboxedMacOS()
}
