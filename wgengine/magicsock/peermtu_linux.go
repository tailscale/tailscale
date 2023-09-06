// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package magicsock

import (
	"net"
	"syscall"

	"tailscale.com/types/nettype"
)

func setDontFragment(pconn nettype.PacketConn, network string) (err error) {
	if c, ok := pconn.(*net.UDPConn); ok {
		rc, err := c.SyscallConn()
		if err == nil {
			rc.Control(func(fd uintptr) {
				if network == "udp4" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
				}
				if network == "udp6" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
				}
			})
		}
	}
	return err
}

func CanPMTUD() bool {
	return debugPMTUD() // only if the envknob is enabled, for now.
}
