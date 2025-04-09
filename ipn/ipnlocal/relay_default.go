// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios

package ipnlocal

import (
	"net/netip"

	"tailscale.com/envknob"
	"tailscale.com/net/udprelay"
	"tailscale.com/tailcfg"
)

func init() {
	// Initialize the relay server constructor on all platforms except iOS (see
	// build tag at top of file) for now as to limit the impact to binary size
	// and resulting effect of pushing up against NetworkExtension limits.
	// Eventually we will want to support the relay server on iOS, specifically
	// on the Apple TV. Apple TVs are well-fitted to act as underlay relay
	// servers as they are effectively always-on servers.
	registerNewRelayServer(func(port int, addrs []netip.Addr) (relayServer, int, error) {
		return udprelay.NewServer(port, addrs)
	})
}

// ShouldRunRelayServer returns true if a relay server port has been set in prefs,
// TAILSCALE_USE_WIP_CODE environment variable is set, and the node has the
// tailcfg.NodeAttrRelayServer tailcfg.NodeCapability.
//
// TODO(jwhited): remove the envknob guard once APIs (peerapi endpoint,
// new disco message types) are stable.
func (b *LocalBackend) ShouldRunRelayServer() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Prefs().RelayServerPort().Valid() && envknob.UseWIPCode() &&
		b.netMap != nil && b.netMap.SelfNode.HasCap(tailcfg.NodeAttrRelayServer)
}
