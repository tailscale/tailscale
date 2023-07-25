// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"io"
	"net"
	"syscall"

	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

// From https://opensource.apple.com/source/xnu/xnu-6153.141.1/bsd/netinet6/in6.h.auto.html
// https://github.com/rust-lang/libc/pull/2613/commits/757b5dd7c7cb4d913e582100c2cd8a5667b9e204

const (
	ipDontFrag   = 28
	ipv6DontFrag = 62
)

func (c *Conn) listenRawDisco(family string) (io.Closer, error) {
	return nil, errors.New("raw disco listening not supported on this OS")
}

func trySetSocketBuffer(pconn nettype.PacketConn, logf logger.Logf) {
	portableTrySetSocketBuffer(pconn, logf)
}

func trySetDontFragment(pconn nettype.PacketConn, network string) (err error) {
	if c, ok := pconn.(*net.UDPConn); ok {
		rc, err := c.SyscallConn()
		if err == nil {
			rc.Control(func(fd uintptr) {
				if network == "udp4" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipDontFrag, 1)
				}
				if network == "udp6" {
					err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, ipv6DontFrag, 1)
				}
			})
		}
	}
	return err
}

func tryEnableUDPOffload(pconn nettype.PacketConn) (hasTX bool, hasRX bool) {
	return false, false
}

func getGSOSizeFromControl(control []byte) (int, error) {
	return 0, nil
}

func setGSOSizeInControl(control *[]byte, gso uint16) {}

func errShouldDisableOffload(err error) bool {
	return false
}

const (
	controlMessageSize = 0
)
