// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package udprelay

import (
	"net"
	"syscall"
)

func trySetReusePort(_ string, _ string, _ syscall.RawConn) {}

func isReusableSocket(*net.UDPConn) bool {
	return false
}
