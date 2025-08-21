// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package sockopts

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
	"tailscale.com/types/nettype"
)

// SetICMPErrImmunity sets socket options on pconn to prevent ICMP reception,
// e.g. ICMP Port Unreachable, from surfacing as a syscall error.
//
// If pconn is not a [*net.UDPConn], then SetICMPErrImmunity is no-op.
func SetICMPErrImmunity(pconn nettype.PacketConn) error {
	c, ok := pconn.(*net.UDPConn)
	if !ok {
		// not a UDP connection; nothing to do
		return nil
	}

	sysConn, err := c.SyscallConn()
	if err != nil {
		return fmt.Errorf("SetICMPErrImmunity: getting SyscallConn failed: %v", err)
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
		return fmt.Errorf("SetICMPErrImmunity: could not set SIO_UDP_NETRESET: %v", ioctlErr)
	}
	if err != nil {
		return fmt.Errorf("SetICMPErrImmunity: SyscallConn.Control failed: %v", err)
	}
	return nil
}
