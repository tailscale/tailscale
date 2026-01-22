// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package udprelay

import (
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/types/nettype"
)

func trySetReusePort(_ string, _ string, c syscall.RawConn) {
	c.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
}

func isReusableSocket(pc nettype.PacketConn) bool {
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return false
	}
	rc, err := sc.SyscallConn()
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
