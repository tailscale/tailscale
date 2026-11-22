// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || android

package androidbin

import (
	"tailscale.com/feature"
	"tailscale.com/net/netmon"
)

// Android apps may register a Java-backed interface getter. This fallback
// is consulted only if no getter is registered and net.Interfaces fails.
func init() {
	if !feature.Register("androidbin") {
		return
	}
	netmon.HookInterfacesFallback.Set(fallbackInterfaces)
}
