// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || ios

package netns

import (
	"errors"
	"log"
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// SetListenConfigInterfaceIndex sets lc.Control such that sockets are bound
// to the provided interface index.
func SetListenConfigInterfaceIndex(lc *net.ListenConfig, ifIndex int) error {
	if lc == nil {
		return errors.New("nil ListenConfig")
	}
	if lc.Control != nil {
		return errors.New("ListenConfig.Control already set")
	}
	lc.Control = func(network, address string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = bindInterface(fd, network, address, ifIndex)
			if sockErr != nil {
				log.Printf("netns: bind(%q, %q) on index %v: %v", network, address, ifIndex, sockErr)
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}
	return nil
}

func bindInterface(fd uintptr, network, address string, ifIndex int) error {
	v6 := strings.Contains(address, "]:") || strings.HasSuffix(network, "6") // hacky test for v6
	proto := unix.IPPROTO_IP
	opt := unix.IP_BOUND_IF
	if v6 {
		proto = unix.IPPROTO_IPV6
		opt = unix.IPV6_BOUND_IF
	}
	return unix.SetsockoptInt(int(fd), proto, opt, ifIndex)
}
