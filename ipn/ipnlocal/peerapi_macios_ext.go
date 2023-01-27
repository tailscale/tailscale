// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_macext && (darwin || ios)

package ipnlocal

import (
	"fmt"
	"net"
	"net/netip"

	"tailscale.com/net/interfaces"
	"tailscale.com/net/netns"
)

func init() {
	initListenConfig = initListenConfigNetworkExtension
}

// initListenConfigNetworkExtension configures nc for listening on IP
// through the iOS/macOS Network/System Extension (Packet Tunnel
// Provider) sandbox.
func initListenConfigNetworkExtension(nc *net.ListenConfig, ip netip.Addr, st *interfaces.State, tunIfName string) error {
	tunIf, ok := st.Interface[tunIfName]
	if !ok {
		return fmt.Errorf("no interface with name %q", tunIfName)
	}
	return netns.SetListenConfigInterfaceIndex(nc, tunIf.Index)
}
