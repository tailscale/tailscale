// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package udprelay

import (
	"net"
	"syscall"
)

func listenControl(_ string, _ string, _ syscall.RawConn) error {
	return nil
}

func isReusableSocket(*net.UDPConn) bool {
	return false
}
