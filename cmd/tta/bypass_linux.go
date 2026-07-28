// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
	"tailscale.com/net/netmon"
)

// bypassControlFunc is set as net.Dialer.Control so that sockets dialed by
// TTA bypass tailscaled's policy routing. Without it, sockets opened before
// tailscaled installs an exit-node route would have their packets rerouted
// via the exit node when the route is later installed, breaking the
// existing connection.
//
// We bind the socket to the default route's interface (typically the VM's
// LAN-facing NIC) rather than relying on the bypass fwmark. The fwmark
// approach is conditional on tailscaled having configured SO_MARK-based
// policy routing; binding to the underlying interface is unconditional.
func bypassControlFunc(network, address string, c syscall.RawConn) error {
	ifc, err := netmon.DefaultRouteInterface()
	if err != nil {
		return fmt.Errorf("netmon.DefaultRouteInterface: %w", err)
	}
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifc)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return fmt.Errorf("setting SO_BINDTODEVICE on %q: %w", ifc, sockErr)
	}
	return nil
}
