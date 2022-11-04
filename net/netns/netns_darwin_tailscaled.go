// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin && !ts_macext

package netns

import (
	"fmt"
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
	if strings.HasPrefix(address, "127.") || address == "::1" {
		// Don't bind to an interface for localhost connections.
		return nil
	}
	idx, err := interfaces.DefaultRouteInterfaceIndex()
	if err != nil {
		logf("[unexpected] netns: DefaultRouteInterfaceIndex: %v", err)
		return nil
	}
	v6 := strings.Contains(address, "]:") || strings.HasSuffix(network, "6") // hacky test for v6
	proto := unix.IPPROTO_IP
	opt := unix.IP_BOUND_IF
	if v6 {
		proto = unix.IPPROTO_IPV6
		opt = unix.IPV6_BOUND_IF
	}

	var sockErr error
	err = c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), proto, opt, idx)
	})
	if err != nil {
		return fmt.Errorf("RawConn.Control on %T: %w", c, err)
	}
	if sockErr != nil {
		logf("[unexpected] netns: control(%q, %q), v6=%v, index=%v: %v", network, address, v6, idx, sockErr)
	}
	return sockErr
}
