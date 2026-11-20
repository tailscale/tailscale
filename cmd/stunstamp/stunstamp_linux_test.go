// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTCPDialReuseAddr(t *testing.T) {
	c := testTCPDial(t)
	raw, err := c.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		value, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil {
		t.Fatal(sockErr)
	}
	if value != 1 {
		t.Errorf("SO_REUSEADDR = %d; want 1", value)
	}
}
