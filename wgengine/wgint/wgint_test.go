// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package wgint

import (
	"net/netip"
	"testing"

	"github.com/tailscale/wireguard-go/device"
)

func TestInternalOffsets(t *testing.T) {
	peer := new(device.Peer)
	if got := peerLastHandshakeNano(peer); got != 0 {
		t.Errorf("PeerLastHandshakeNano = %v, want 0", got)
	}
	if got := peerRxBytes(peer); got != 0 {
		t.Errorf("PeerRxBytes = %v, want 0", got)
	}
	if got := peerTxBytes(peer); got != 0 {
		t.Errorf("PeerTxBytes = %v, want 0", got)
	}
	if got := peerHandshakeAttempts(peer); got != 0 {
		t.Errorf("PeerHandshakeAttempts = %v, want 0", got)
	}
	if got := peerEndpoint(peer); got != nil {
		t.Errorf("peerEndpoint = %v, want nil", got)
	}
	peer.SetEndpointFromPacket(fakeEndpoint{})
	if got := peerEndpoint(peer); got != (fakeEndpoint{}) {
		t.Errorf("peerEndpoint = %v, want fakeEndpoint{}", got)
	}
}

// fakeEndpoint is a no-op [conn.Endpoint].
type fakeEndpoint struct{}

func (fakeEndpoint) ClearSrc()           {}
func (fakeEndpoint) SrcToString() string { return "" }
func (fakeEndpoint) DstToString() string { return "" }
func (fakeEndpoint) DstToBytes() []byte  { return nil }
func (fakeEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (fakeEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
