// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"os/user"
	"strconv"

	"tailscale.com/util/osuser"
)

// userMeta is a wrapper around *user.User with extra fields.
type userMeta struct {
	user.User

	// loginShellCached is the user's login shell, if known
	// at the time of userLookup.
	loginShellCached string
}

// userLookup is like os/user.Lookup but it returns a *userMeta wrapper
// around a *user.User with extra fields.
func userLookup(username string) (*userMeta, error) {
	// getent accepts numeric UIDs as well as names. Use the same semantics
	// in the os/user fallback, rather than looking a UID up as a name.
	lookup := osuser.LookupByUsernameWithShell
	if _, err := strconv.ParseUint(username, 10, 32); err == nil {
		lookup = osuser.LookupByUIDWithShell
	}
	u, s, err := lookup(username)
	if err != nil {
		return nil, err
	}

	return &userMeta{User: *u, loginShellCached: s}, nil
}
