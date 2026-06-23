// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgengine

import (
	"errors"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/wgint"
)

// DebugActiveEndpoints implements [Engine].
//
// The set of peers is enumerated from magicsock's peer map (which mirrors the
// netmap); for each, the corresponding wireguard-go peer is looked up without
// triggering wireguard-go's lazy on-demand peer creation. wgcfg.ReconfigDevice
// keeps the device's peers a subset of the configured (netmap) peers, so this
// covers every wireguard-go peer that can exist.
func (e *userspaceEngine) DebugActiveEndpoints() (*ipnstate.DebugActiveEndpoints, error) {
	peers := e.magicConn.DebugActiveEndpoints()

	e.wgLock.Lock()
	dev := e.wgdev
	e.wgLock.Unlock()
	if dev == nil {
		return nil, errors.New("no wireguard-go device")
	}
	for i := range peers {
		p := &peers[i]
		// Use LookupActivePeer (not LookupPeer) to avoid lazily
		// creating a wireguard-go peer for every netmap peer; absence
		// is itself the signal reported by a nil WireGuard field.
		wgp, ok := dev.LookupActivePeer(p.NodeKey.Raw32())
		if !ok {
			continue
		}
		wp := wgint.PeerOf(wgp)
		st := &ipnstate.WireGuardPeerState{
			LastHandshake: wp.LastHandshake(),
			RxBytes:       wp.RxBytes(),
			TxBytes:       wp.TxBytes(),
		}
		if ep := wp.Endpoint(); ep != nil {
			st.Endpoint = ep.DstToString()
			if magicsock.IsMagicsockEndpoint(ep) {
				st.EndpointType = ipnstate.WireGuardEndpointTypeMagicsock
			} else {
				st.EndpointType = ipnstate.WireGuardEndpointTypeOther
			}
		}
		p.WireGuard = st
	}
	return &ipnstate.DebugActiveEndpoints{Peers: peers}, nil
}
