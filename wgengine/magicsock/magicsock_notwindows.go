// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package magicsock

import (
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

func trySetUDPSocketOptions(pconn nettype.PacketConn, logf logger.Logf) {}
