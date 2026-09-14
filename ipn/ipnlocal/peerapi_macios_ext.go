// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_macext && (darwin || ios)

package ipnlocal

import (
	"fmt"
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
	// A zero ifaceIndex is invalid for peerapi. A zero value will not get us
	// out of the network sandbox. Caller should log and retry.
	if ifaceIndex == 0 {
		return fmt.Errorf("peerapi: cannot listen on %s with ifaceIndex 0", ip)
	}
	return netns.SetListenConfigInterfaceIndex(nc, ifaceIndex)
}
