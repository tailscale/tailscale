// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net"
	"syscall"

	"tailscale.com/types/nettype"
)

const (
	// From https://opensource.apple.com/source/xnu/xnu-6153.141.1/bsd/netinet6/in6.h.auto.html
	socketOptionIPDontFrag   = 28
	socketOptionIPv6DontFrag = 62
)

func setDontFragment(pconn nettype.PacketConn, network string) (err error) {
	if c, ok := pconn.(*net.UDPConn); ok {
		rc, err := c.SyscallConn()
		if err == nil {
			rc.Control(func(fd uintptr) {
				if network == "udp4" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, socketOptionIPDontFrag, 1)
				}
				if network == "udp6" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, socketOptionIPDontFrag, 1)
				}
			})
		}
	}
	return err
}
