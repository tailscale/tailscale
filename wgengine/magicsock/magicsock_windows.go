// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package magicsock

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

func trySetUDPSocketOptions(pconn nettype.PacketConn, logf logger.Logf) {
	c, ok := pconn.(*net.UDPConn)
	if !ok {
		// not a UDP connection; nothing to do
		return
	}

	sysConn, err := c.SyscallConn()
	if err != nil {
		logf("trySetUDPSocketOptions: getting SyscallConn failed: %v", err)
		return
	}

	// Similar to https://github.com/golang/go/issues/5834 (which involved
	// WSAECONNRESET), Windows can return a WSAENETRESET error, even on UDP
	// reads. Disable this.
	const SIO_UDP_NETRESET = windows.IOC_IN | windows.IOC_VENDOR | 15

	var ioctlErr error
	err = sysConn.Control(func(fd uintptr) {
		ret := uint32(0)
		flag := uint32(0)
		size := uint32(unsafe.Sizeof(flag))
		ioctlErr = windows.WSAIoctl(
			windows.Handle(fd),
			SIO_UDP_NETRESET,               // iocc
			(*byte)(unsafe.Pointer(&flag)), // inbuf
			size,                           // cbif
			nil,                            // outbuf
			0,                              // cbob
			&ret,                           // cbbr
			nil,                            // overlapped
			0,                              // completionRoutine
		)
	})
	if ioctlErr != nil {
		logf("trySetUDPSocketOptions: could not set SIO_UDP_NETRESET: %v", ioctlErr)
	}
	if err != nil {
		logf("trySetUDPSocketOptions: SyscallConn.Control failed: %v", err)
	}
}
