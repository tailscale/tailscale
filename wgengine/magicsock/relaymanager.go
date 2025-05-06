// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"sync"

	"tailscale.com/disco"
	"tailscale.com/types/key"
)

// relayManager manages allocation and handshaking of
// [tailscale.com/net/udprelay.Server] endpoints. The zero value is ready for
// use.
type relayManager struct {
	mu                     sync.Mutex // guards the following fields
	discoInfoByServerDisco map[key.DiscoPublic]*discoInfo
}

func (h *relayManager) initLocked() {
	if h.discoInfoByServerDisco != nil {
		return
	}
	h.discoInfoByServerDisco = make(map[key.DiscoPublic]*discoInfo)
}

// discoInfo returns a [*discoInfo] for 'serverDisco' if there is an
// active/ongoing handshake with it, otherwise it returns nil, false.
func (h *relayManager) discoInfo(serverDisco key.DiscoPublic) (_ *discoInfo, ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.initLocked()
	di, ok := h.discoInfoByServerDisco[serverDisco]
	return di, ok
}

func (h *relayManager) handleCallMeMaybeVia(dm *disco.CallMeMaybeVia) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.initLocked()
	// TODO(jwhited): implement
}

func (h *relayManager) handleBindUDPRelayEndpointChallenge(dm *disco.BindUDPRelayEndpointChallenge, di *discoInfo, src netip.AddrPort, vni uint32) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.initLocked()
	// TODO(jwhited): implement
}
