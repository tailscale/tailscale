//go:build js

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"github.com/pion/webrtc/v4"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
)

func newManagerBase(b magicsock.WebRTCBackend) *manager {
	// Configure WebRTC with STUN only
	settingEngine := webrtc.SettingEngine{}

	// Create API with setting engine
	api := webrtc.NewAPI(
		webrtc.WithSettingEngine(settingEngine),
	)

	return &manager{
		logf:                   b.Logf,
		b:                      b,
		peerConnectionsByPeer:  make(map[magicsock.WebRTCPeer]*peerState),
		peerConnectionsByDisco: make(map[key.DiscoPublic]*peerState),
		startConnectionCh:      make(chan magicsock.WebRTCPeer, 256),
		connectionReadyCh:      make(chan connectionReadyEvent, 16),
		closeCh:                make(chan struct{}),
		runLoopStoppedCh:       make(chan struct{}),
		api:                    api,
	}
}
