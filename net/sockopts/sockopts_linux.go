// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package sockopts

import (
	"net"
	"syscall"

	"tailscale.com/types/nettype"
)

// SetBufferSize sets pconn's buffer to size for direction. It attempts
// (errForce) to set SO_SNDBUFFORCE or SO_RECVBUFFORCE which can overcome the
// limit of net.core.{r,w}mem_max, but require CAP_NET_ADMIN. It falls back to
// the portable implementation (errPortable) if that fails, which may be
// silently capped to net.core.{r,w}mem_max.
//
// If pconn is not a [*net.UDPConn], then SetBufferSize is no-op.
func SetBufferSize(pconn nettype.PacketConn, direction BufferDirection, size int) (errForce error, errPortable error) {
	forceOpt := syscall.SO_RCVBUFFORCE
	getOpt := syscall.SO_RCVBUF
	if direction == WriteDirection {
		forceOpt = syscall.SO_SNDBUFFORCE
		getOpt = syscall.SO_SNDBUF
	}
	if c, ok := pconn.(*net.UDPConn); ok {
		var rc syscall.RawConn
		rc, errForce = c.SyscallConn()
		if errForce == nil {
			rc.Control(func(fd uintptr) {
				// On Linux, getsockopt reports 2x the actual buffer size to
				// account for kernel bookkeeping overhead. Skip if the buffer
				// is already at least as large as the requested size.
				current, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, getOpt)
				if err == nil && current >= size*2 {
					return
				}
				errForce = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, forceOpt, size)
			})
		}
		if errForce != nil {
			errPortable = portableSetBufferSize(pconn, direction, size)
		}
	}
	return errForce, errPortable
}
