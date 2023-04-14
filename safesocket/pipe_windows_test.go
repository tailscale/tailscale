// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

import "tailscale.com/util/winutil"

func init() {
	// downgradeSDDL is a test helper that downgrades the windowsSDDL variable if
	// the currently running user does not have sufficient priviliges to set the
	// SDDL.
	downgradeSDDL = func() (cleanup func()) {
		// The current default descriptor can not be set by mere mortal users,
		// so we need to undo that for executing tests as a regular user.
		if !winutil.IsCurrentProcessElevated() {
			var orig string
			orig, windowsSDDL = windowsSDDL, ""
			return func() { windowsSDDL = orig }
		}
		return func() {}
	}
}
