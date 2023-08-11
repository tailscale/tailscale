// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package magicsock

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/types/nettype"
)

func setDontFragment(pconn nettype.PacketConn, network string) (err error) {
	if c, ok := pconn.(*net.UDPConn); ok {
		rc, err := c.SyscallConn()
		if err == nil {
			rc.Control(func(fd uintptr) {
				if network == "udp4" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, unix.IP_DONTFRAG, 1)
				}
				if network == "udp6" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, unix.IPV6_DONTFRAG, 1)
				}
			})
		}
	}
	return err
}

func CanPMTUD() bool {
	return debugPMTUD() // only if the envknob is for now.
}
