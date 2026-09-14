// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package ipnlocal

import (
	"net"
	"net/netip"

	"tailscale.com/net/netns"
)

func init() {
	initListenConfig = initListenConfigTun
}

// initListenConfigTun binds the peerapi listener to the tunnel interface
// with SO_BINDTODEVICE.
//
// Linux delivers a packet addressed to the node's own Tailscale IP via
// INPUT from any interface it arrives on (weak host model), so a
// LAN-adjacent attacker could otherwise complete a TCP handshake with
// the kernel-level listener, confirming that this machine's MAC
// address belongs to a given tailnet identity (the peerapi port is
// derived from the Tailscale IP). Binding the listener to the tunnel
// interface drops those handshakes at socket lookup. macOS and iOS
// already bind this listener to the tunnel interface with IP_BOUND_IF,
// and Windows is protected by its strong host model.
//
// No legitimate traffic is lost. Connections to the node's Tailscale
// IP from the local host are delivered via the tunnel interface, peer
// connections arrive that way in builds without userspace netstack,
// and with netstack compiled in (the usual case) peer connections are
// terminated in userspace and never reach the kernel listener at all.
// In netstack mode there is no tunnel interface and the listener binds
// all addresses; the only connections that reach it are loopback dials
// from netstack and from the local host, so loopback is the right
// device there.
func initListenConfigTun(config *net.ListenConfig, addr netip.Addr, tunIfIndex int) error {
	device := "lo"
	if tunIfIndex != 0 {
		iface, err := net.InterfaceByIndex(tunIfIndex)
		if err == nil {
			device = iface.Name
		}
	}
	return netns.SetListenConfigInterfaceName(config, device)
}
