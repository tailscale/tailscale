// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"tailscale.com/ipn"
)

// Actor is any actor using the [ipnlocal.LocalBackend].
//
// It typically represents a specific OS user, indicating that an operation
// is performed on behalf of this user, should be evaluated against their
// access rights, and performed in their security context when applicable.
type Actor interface {
	// UserID returns an OS-specific UID of the user represented by the receiver,
	// or "" if the actor does not represent a specific user on a multi-user system.
	// As of 2024-08-27, it is only used on Windows.
	UserID() ipn.WindowsUserID
	// Username returns the user name associated with the receiver,
	// or "" if the actor does not represent a specific user.
	Username() (string, error)

	// IsLocalSystem reports whether the actor is the Windows' Local System account.
	//
	// Deprecated: this method exists for compatibility with the current (as of 2024-08-27)
	// permission model and will be removed as we progress on tailscale/corp#18342.
	IsLocalSystem() bool

	// IsLocalAdmin reports whether the actor has administrative access to the
	// local machine, for whatever that means with respect to the current OS.
	//
	// The operatorUID is only used on Unix-like platforms and specifies the ID
	// of a local user (in the os/user.User.Uid string form) who is allowed to
	// operate tailscaled without being root or using sudo.
	//
	// Deprecated: this method exists for compatibility with the current (as of 2024-08-27)
	// permission model and will be removed as we progress on tailscale/corp#18342.
	IsLocalAdmin(operatorUID string) bool
}

// ActorCloser is an optional interface that might be implemented by an [Actor]
// that must be closed when done to release the resources.
type ActorCloser interface {
	// Close releases resources associated with the receiver.
	Close() error
}
