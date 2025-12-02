// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package udprelay

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenControl(_ string, _ string, c syscall.RawConn) error {
	c.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	return nil
}

func isReusableSocket(uc *net.UDPConn) bool {
	rc, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var reusable bool
	rc.Control(func(fd uintptr) {
		val, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT)
		if err == nil && val == 1 {
			reusable = true
		}
	})
	return reusable
}
