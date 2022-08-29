// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgint

import (
	"testing"

	"golang.zx2c4.com/wireguard/device"
)

func TestPeerStats(t *testing.T) {
	peer := new(device.Peer)
	if got := PeerLastHandshakeNano(peer); got != 0 {
		t.Errorf("PeerLastHandshakeNano = %v, want 0", got)
	}
	if got := PeerRxBytes(peer); got != 0 {
		t.Errorf("PeerRxBytes = %v, want 0", got)
	}
	if got := PeerTxBytes(peer); got != 0 {
		t.Errorf("PeerTxBytes = %v, want 0", got)
	}
}
