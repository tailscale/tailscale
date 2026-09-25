// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package magicsock

import (
	"syscall"

	"tailscale.com/types/nettype"
)

func getDontFragOpt(network string) int {
	if network == "udp4" {
		return syscall.IP_MTU_DISCOVER
	}
	return syscall.IPV6_MTU_DISCOVER
}

func (c *Conn) setDontFragment(network string, enable bool) error {
	return c.setDontFragmentOn(c.mainPacketConn(network), network, enable)
}

// setDontFragmentOn sets the DF bit socket option on pconn, a socket of the
// given network ("udp4" or "udp6").
func (c *Conn) setDontFragmentOn(pconn nettype.PacketConn, network string, enable bool) error {
	optArg := syscall.IP_PMTUDISC_DO
	if enable == false {
		optArg = syscall.IP_PMTUDISC_DONT
	}
	var err error
	rcErr := packetConnControl(pconn, func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), getIPProto(network), getDontFragOpt(network), optArg)
	})

	if rcErr != nil {
		return rcErr
	}
	return err
}

func (c *Conn) getDontFragment(network string) (bool, error) {
	var v int
	var err error
	rcErr := c.connControl(network, func(fd uintptr) {
		v, err = syscall.GetsockoptInt(int(fd), getIPProto(network), getDontFragOpt(network))
	})

	if rcErr != nil {
		return false, rcErr
	}
	if v == syscall.IP_PMTUDISC_DO {
		return true, err
	}
	return false, err
}
