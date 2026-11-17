// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package sockopts

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/types/nettype"
)

// CanShareUDPPort reports whether this platform spreads inbound datagrams
// across several UDP sockets sharing one local port.
const CanShareUDPPort = true

// SetReusePort sets SO_REUSEPORT on the socket underlying c.
func SetReusePort(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return serr
}

// SetBufferSize sets pconn's buffer to size for direction. It attempts
// (errForce) to set SO_SNDBUFFORCE or SO_RECVBUFFORCE which can overcome the
// limit of net.core.{r,w}mem_max, but require CAP_NET_ADMIN. It falls back to
// the portable implementation (errPortable) if that fails, which may be
// silently capped to net.core.{r,w}mem_max.
//
// If pconn is not a [*net.UDPConn], then SetBufferSize is no-op.
func SetBufferSize(pconn nettype.PacketConn, direction BufferDirection, size int) (errForce error, errPortable error) {
	opt := syscall.SO_RCVBUFFORCE
	if direction == WriteDirection {
		opt = syscall.SO_SNDBUFFORCE
	}
	if c, ok := pconn.(*net.UDPConn); ok {
		var rc syscall.RawConn
		rc, errForce = c.SyscallConn()
		if errForce == nil {
			rc.Control(func(fd uintptr) {
				errForce = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, opt, size)
			})
		}
		if errForce != nil {
			errPortable = portableSetBufferSize(pconn, direction, size)
		}
	}
	return errForce, errPortable
}
