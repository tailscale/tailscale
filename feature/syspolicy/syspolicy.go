// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package syspolicy provides an interface for system-wide policy management.
package syspolicy

import (
	"tailscale.com/feature"

	_ "tailscale.com/util/syspolicy" // for its registration side effects
)

func init() {
	feature.Register("syspolicy")
}
