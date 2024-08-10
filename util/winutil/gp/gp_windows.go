// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package gp contains [Group Policy]-related functions and types.
//
// [Group Policy]: https://web.archive.org/web/20240630210707/https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-start-page
package gp

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// Scope is a user or machine policy scope.
type Scope int

const (
	// MachinePolicy indicates a machine policy.
	// Registry-based machine policies reside in HKEY_LOCAL_MACHINE.
	MachinePolicy Scope = iota
	// UserPolicy indicates a user policy.
	// Registry-based user policies reside in HKEY_CURRENT_USER of the corresponding user.
	UserPolicy
)

// _RP_FORCE causes RefreshPolicyEx to reapply policy even if no policy change was detected.
// See [RP_FORCE] for details.
//
// [RP_FORCE]: https://web.archive.org/save/https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-refreshpolicyex
const _RP_FORCE = 0x1

// RefreshUserPolicy triggers a machine policy refresh, but does not wait for it to complete.
// When the force parameter is true, it causes the Group Policy to reapply policy even
// if no policy change was detected.
func RefreshMachinePolicy(force bool) error {
	return refreshPolicyEx(true, toRefreshPolicyFlags(force))
}

// RefreshUserPolicy triggers a user policy refresh, but does not wait for it to complete.
// When the force parameter is true, it causes the Group Policy to reapply policy even
// if no policy change was detected.
//
// The token indicates user whose policy should be refreshed.
// If specified, the token must be either a primary token with TOKEN_QUERY and TOKEN_DUPLICATE
// access, or an impersonation token with TOKEN_QUERY and TOKEN_IMPERSONATE access,
// and the specified user must be logged in interactively.
//
// Otherwise, a zero token value indicates the current user. It should not
// be used by services or other applications running under system identities.
//
// The function fails with windows.ERROR_ACCESS_DENIED if the user represented by the token
// is not logged in interactively at the time of the call.
func RefreshUserPolicy(token windows.Token, force bool) error {
	if token != 0 {
		// Impersonate the user whose policy we need to refresh.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := impersonateLoggedOnUser(token); err != nil {
			return err
		}
		defer func() {
			if err := windows.RevertToSelf(); err != nil {
				// RevertToSelf errors are non-recoverable.
				panic(fmt.Errorf("could not revert impersonation: %w", err))
			}
		}()
	}

	return refreshPolicyEx(true, toRefreshPolicyFlags(force))
}

func toRefreshPolicyFlags(force bool) uint32 {
	if force {
		return _RP_FORCE
	}
	return 0
}
