// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || ios
// +build darwin ios

package netns

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
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

func control(logf logger.Logf) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		return controlLogf(logf, network, address, c)
	}
}

// controlLogf marks c as necessary to dial in a separate network namespace.
//
// It's intentionally the same signature as net.Dialer.Control
// and net.ListenConfig.Control.
func controlLogf(logf logger.Logf, network, address string, c syscall.RawConn) error {
	if strings.HasPrefix(address, "127.") || address == "::1" {
		// Don't bind to an interface for localhost connections.
		return nil
	}
	idx, err := interfaces.DefaultRouteInterfaceIndex()
	if err != nil {
		logf("[unexpected] netns: DefaultRouteInterfaceIndex: %v", err)
		return nil
	}
	var sockErr error
	err = c.Control(func(fd uintptr) {
		sockErr = bindInterface(fd, network, address, idx)
	})
	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	if sockErr != nil {
		logf("[unexpected] netns: control(%q, %q), index=%v: %v", network, address, idx, sockErr)
	}
	return sockErr
}
