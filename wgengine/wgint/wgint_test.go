// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgint

import (
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
}
