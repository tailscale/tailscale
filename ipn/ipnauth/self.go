// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import "tailscale.com/ipn"

// Self is a caller identity that represents the tailscaled itself and therefore has unlimited access.
//
// It's typically used for operations performed by tailscaled on its own,
// or upon a request from the control plane, rather on behalf of a specific user.
var Self Identity = unrestricted{}

// IsUnrestricted reports whether the specified identity has unrestricted access to the LocalBackend,
// including all user profiles and preferences, serving as a performance optimization
// and ensuring that tailscaled operates correctly, unaffected by Group Policy, MDM, or similar restrictions.
func IsUnrestricted(identity Identity) bool {
	if _, ok := identity.(unrestricted); ok {
		return true
	}
	return false
}

type unrestricted struct {
}

// UserID returns an empty string.
func (unrestricted) UserID() ipn.WindowsUserID {
	return ""
}

// Username returns an empty string.
func (unrestricted) Username() (string, error) {
	return "", nil
}

// CheckAccess always allows the requested access.
func (unrestricted) CheckAccess(desired DeviceAccess) AccessCheckResult {
	return AllowAccess()
}

// CheckProfileAccess always allows the requested profile access.
func (unrestricted) CheckProfileAccess(profile ipn.LoginProfileView, prefs ipn.PrefsGetter, requested ProfileAccess) AccessCheckResult {
	return AllowAccess()
}
