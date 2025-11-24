// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_macext && (darwin || ios)

package ipnlocal

import (
	"net"
	"net/netip"

	"tailscale.com/net/netns"
)

func init() {
	initListenConfig = initListenConfigNetworkExtension
}

// initListenConfigNetworkExtension configures nc for listening on IP
// through the iOS/macOS Network/System Extension (Packet Tunnel
// Provider) sandbox.
func initListenConfigNetworkExtension(nc *net.ListenConfig, ip netip.Addr, ifaceIndex int) error {
	return netns.SetListenConfigInterfaceIndex(nc, ifaceIndex)
}
