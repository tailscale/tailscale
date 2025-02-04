// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"tailscale.com/ipn"
)

// Self is a caller identity that represents the tailscaled itself and therefore
// has unlimited access.
var Self Actor = unrestricted{}

// unrestricted is an [Actor] that has unlimited access to the currently running
// tailscaled instance. It's typically used for operations performed by tailscaled
// on its own, or upon a request from the control plane, rather on behalf of a user.
type unrestricted struct{}

// UserID implements [Actor].
func (u unrestricted) UserID() ipn.WindowsUserID { return "" }

// Username implements [Actor].
func (u unrestricted) Username() (string, error) { return "", nil }

// ClientID implements [Actor].
// It always returns (NoClientID, false) because the tailscaled itself
// is not a connected LocalAPI client.
func (u unrestricted) ClientID() (_ ClientID, ok bool) { return NoClientID, false }

// CheckProfileAccess implements [Actor].
func (u unrestricted) CheckProfileAccess(_ ipn.LoginProfileView, _ ProfileAccess, _ AuditLogFunc) error {
	// Unrestricted access to all profiles.
	return nil
}

// IsLocalSystem implements [Actor].
//
// Deprecated: this method exists for compatibility with the current (as of 2025-01-28)
// permission model and will be removed as we progress on tailscale/corp#18342.
func (u unrestricted) IsLocalSystem() bool { return false }

// IsLocalAdmin implements [Actor].
//
// Deprecated: this method exists for compatibility with the current (as of 2025-01-28)
// permission model and will be removed as we progress on tailscale/corp#18342.
func (u unrestricted) IsLocalAdmin(operatorUID string) bool { return false }
