// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailfs

import "tailscale.com/version"

// AutomountSupported reports whether TailFS automounting is supported on this
// system.
func AutomountSupported() bool {
	return DefaultAutomountPath() != "" && !version.IsSandboxedMacOS()
}
