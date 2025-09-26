// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package feature

// HookCanAutoUpdate is a hook for the clientupdate package
// to conditionally initialize.
var HookCanAutoUpdate Hook[func() bool]

// CanAutoUpdate reports whether the current binary is built with auto-update
// support and, if so, whether the current platform supports it.
func CanAutoUpdate() bool {
	if f, ok := HookCanAutoUpdate.GetOk(); ok {
		return f()
	}
	return false
}
