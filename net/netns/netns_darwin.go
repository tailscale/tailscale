// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

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
	if isLocalhost(address) {
		// Don't bind to an interface for localhost connections.
		return nil
	}
	idx, err := interfaces.DefaultRouteInterfaceIndex()
	if err != nil {
		logf("[unexpected] netns: DefaultRouteInterfaceIndex: %v", err)
		return nil
	}

	return bindConnToInterface(c, network, address, idx, logf)
}

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
		return bindConnToInterface(c, network, address, ifIndex, log.Printf)
	}
	return nil
}

func bindConnToInterface(c syscall.RawConn, network, address string, ifIndex int, logf logger.Logf) error {
	v6 := strings.Contains(address, "]:") || strings.HasSuffix(network, "6") // hacky test for v6
	proto := unix.IPPROTO_IP
	opt := unix.IP_BOUND_IF
	if v6 {
		proto = unix.IPPROTO_IPV6
		opt = unix.IPV6_BOUND_IF
	}

	var sockErr error
	err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), proto, opt, ifIndex)
	})
	if sockErr != nil {
		logf("[unexpected] netns: bindConnToInterface(%q, %q), v6=%v, index=%v: %v", network, address, v6, ifIndex, sockErr)
	}
	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	return sockErr
}
