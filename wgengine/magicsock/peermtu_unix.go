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

// connControl runs the system call fn on the fds of the sockets underlying the
// Conn specified by the string network, which must be "udp4" or "udp6".
// See [sockopts.ControlEach] for what it returns.
func (c *Conn) connControl(network string, fn func(fd uintptr) error) error {
	pconn := &c.pconn4
	if network == "udp6" {
		pconn = &c.pconn6
	}
	return pconn.controlEach(fn)
}

// setDontFragment sets or clears the don't fragment bit on the network sockets.
// Network must be "udp4" or "udp6".
func (c *Conn) setDontFragment(network string, enable bool) error {
	optArg := dontFragEnabled
	if !enable {
		optArg = dontFragDisabled
	}
	return c.connControl(network, func(fd uintptr) error {
		return syscall.SetsockoptInt(int(fd), getIPProto(network), getDontFragOpt(network), optArg)
	})
}

// getDontFragment reports whether the network sockets have the don't fragment bit set.
// It reports false if any socket could not be read.
func (c *Conn) getDontFragment(network string) (bool, error) {
	allSet := true
	err := c.connControl(network, func(fd uintptr) error {
		v, err := syscall.GetsockoptInt(int(fd), getIPProto(network), getDontFragOpt(network))
		if err != nil {
			return err
		}
		if v != dontFragEnabled {
			allSet = false
		}
		return nil
	})
	return err == nil && allSet, err
}
