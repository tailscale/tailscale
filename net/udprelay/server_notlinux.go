// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package udprelay

import (
	"syscall"

	"tailscale.com/types/nettype"
)

func trySetReusePort(_ string, _ string, _ syscall.RawConn) {}

func isReusableSocket(nettype.PacketConn) bool {
	return false
}
