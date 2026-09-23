// Copyright (c) Tailscale Inc & contributors
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

// copyDontFragment gives rc, a connected socket being dialled for network, the shared socket's current don't-fragment setting. UpdatePMTUD redials connected sockets when it changes that setting.
func (c *Conn) copyDontFragment(network string, rc syscall.RawConn) error {
	ruc := &c.pconn4
	if network == "udp6" {
		ruc = &c.pconn6
	}
	sc, ok := ruc.currentConn().(syscall.Conn)
	if !ok {
		return nil // nothing to copy from
	}
	src, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var v int
	var gerr, serr error
	if err := src.Control(func(fd uintptr) {
		v, gerr = syscall.GetsockoptInt(int(fd), getIPProto(network), getDontFragOpt(network))
	}); err != nil {
		return err
	}
	if gerr != nil {
		return gerr
	}
	if err := rc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), getIPProto(network), getDontFragOpt(network), v)
	}); err != nil {
		return err
	}
	return serr
}
