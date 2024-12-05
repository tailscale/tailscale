// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (darwin && !ios) || (linux && !android)

package magicsock

import (
	"syscall"
)

// getIPProto returns the value of the get/setsockopt proto argument necessary
// to set an IP sockopt that corresponds with the string network, which must be
// "udp4" or "udp6".
func getIPProto(network string) int {
	if network == "udp4" {
		return syscall.IPPROTO_IP
	}
	return syscall.IPPROTO_IPV6
}

// connControl allows the caller to run a system call on the socket underlying
// Conn specified by the string network, which must be "udp4" or "udp6". If the
// pconn type implements the syscall method, this function returns the value of
// of the system call fn called with the fd of the socket as its arg (or the
// error from rc.Control() if that fails). Otherwise it returns the error
// errUnsupportedConnType.
func (c *Conn) connControl(network string, fn func(fd uintptr)) error {
	pconn := c.pconn4.pconn
	if network == "udp6" {
		pconn = c.pconn6.pconn
	}
	sc, ok := pconn.(syscall.Conn)
	if !ok {
		return errUnsupportedConnType
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(fn)
}
