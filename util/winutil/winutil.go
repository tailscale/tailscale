// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package winutil contains misc Windows/Win32 helper functions.
package winutil

import (
	"os/user"
)

// RegBase is the registry path inside HKEY_LOCAL_MACHINE where registry settings
// are stored. This constant is a non-empty string only when GOOS=windows.
const RegBase = regBase

// GetPolicyString looks up a registry value in the local machine's path for
// system policies, or returns the given default if it can't.
// Use this function to read values that may be set by sysadmins via the MSI
// installer or via GPO. For registry settings that you do *not* want to be
// visible to sysadmin tools, use GetRegString instead.
//
// This function will only work on GOOS=windows. Trying to run it on any other
// OS will always return the default value.
func GetPolicyString(name, defval string) string {
	return getPolicyString(name, defval)
}

// GetPolicyInteger looks up a registry value in the local machine's path for
// system policies, or returns the given default if it can't.
// Use this function to read values that may be set by sysadmins via the MSI
// installer or via GPO. For registry settings that you do *not* want to be
// visible to sysadmin tools, use GetRegInteger instead.
//
// This function will only work on GOOS=windows. Trying to run it on any other
// OS will always return the default value.
func GetPolicyInteger(name string, defval uint64) uint64 {
	return getPolicyInteger(name, defval)
}

// GetRegString looks up a registry path in the local machine path, or returns
// the given default if it can't.
//
// This function will only work on GOOS=windows. Trying to run it on any other
// OS will always return the default value.
func GetRegString(name, defval string) string {
	return getRegString(name, defval)
}

// GetRegInteger looks up a registry path in the local machine path, or returns
// the given default if it can't.
//
// This function will only work on GOOS=windows. Trying to run it on any other
// OS will always return the default value.
func GetRegInteger(name string, defval uint64) uint64 {
	return getRegInteger(name, defval)
}

// IsSIDValidPrincipal determines whether the SID contained in uid represents a
// type that is a valid security principal under Windows. This check helps us
// work around a bug in the standard library's Windows implementation of
// LookupId in os/user.
// See https://github.com/tailscale/tailscale/issues/869
//
// This function will only work on GOOS=windows. Trying to run it on any other
// OS will always return false.
func IsSIDValidPrincipal(uid string) bool {
	return isSIDValidPrincipal(uid)
}

// LookupPseudoUser attempts to resolve the user specified by uid by checking
// against well-known pseudo-users on Windows. This is a temporary workaround
// until https://github.com/golang/go/issues/49509 is resolved and shipped.
//
// This function will only work on GOOS=windows. Trying to run it on any other
// OS will always return an error.
func LookupPseudoUser(uid string) (*user.User, error) {
	return lookupPseudoUser(uid)
}

// RegisterForRestartOpts supplies options to RegisterForRestart.
type RegisterForRestartOpts struct {
	RestartOnCrash   bool     // When true, this program will be restarted after a crash.
	RestartOnHang    bool     // When true, this program will be restarted after a hang.
	RestartOnUpgrade bool     // When true, this program will be restarted after an upgrade.
	RestartOnReboot  bool     // When true, this program will be restarted after a reboot.
	UseCmdLineArgs   bool     // When true, CmdLineArgs will be used as the program's arguments upon restart. Otherwise no arguments will be provided.
	CmdLineArgs      []string // When UseCmdLineArgs == true, contains the command line arguments, excluding the executable name itself. If nil or empty, the arguments from the current process will be re-used.
}

// RegisterForRestart registers the current process' restart preferences with
// the Windows Restart Manager. This enables the OS to intelligently restart
// the calling executable as requested via opts. This should be called by any
// programs which need to be restarted by the installer post-update.
//
// This function may be called multiple times; the opts from the most recent
// call will override those from any previous invocations.
//
// This function will only work on GOOS=windows. Trying to run it on any other
// OS will always return nil.
func RegisterForRestart(opts RegisterForRestartOpts) error {
	return registerForRestart(opts)
}
