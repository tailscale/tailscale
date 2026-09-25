// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux && !(darwin && !ios)

package batching

import (
	"tailscale.com/control/controlknobs"
	"tailscale.com/types/nettype"
)

// TryUpgradeToConn is no-op on all platforms except Linux and macOS.
func TryUpgradeToConn(pconn nettype.PacketConn, _ string, _ string, _ *controlknobs.Knobs) nettype.PacketConn {
	return pconn
}

// TryUpgradeConnectedToConn is no-op on all platforms except Linux and macOS.
func TryUpgradeConnectedToConn(pconn nettype.PacketConn, _ string, _ *controlknobs.Knobs) nettype.PacketConn {
	return pconn
}

// MaxBatchSize returns the number of datagrams a [Conn] returned by
// [TryUpgradeToConn] on this platform can read or write per syscall, or 1 if
// no upgrade is possible. It is always 1 here.
func MaxBatchSize() int {
	return 1
}
