// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package magicsock

import (
	"tailscale.com/types/nettype"
)

func tryUpgradeToBatchingConn(pconn nettype.PacketConn, _ string, _ int) nettype.PacketConn {
	return pconn
}
