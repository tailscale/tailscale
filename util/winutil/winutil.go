// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package winutil contains misc Windows/Win32 helper functions.
package winutil

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
