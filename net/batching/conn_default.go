// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package batching

import (
	"tailscale.com/control/controlknobs"
	"tailscale.com/types/nettype"
)

// TryUpgradeToConn is no-op on all platforms except linux.
func TryUpgradeToConn(pconn nettype.PacketConn, _ string, _ string, _ *controlknobs.Knobs) nettype.PacketConn {
	return pconn
}
