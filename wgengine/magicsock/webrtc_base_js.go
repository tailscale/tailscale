//go:build js

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"github.com/pion/webrtc/v4"
	"tailscale.com/types/key"
)

func newWebRTCManagerBase(c *Conn) *webrtcManager {
	// Configure WebRTC with STUN only
	settingEngine := webrtc.SettingEngine{}

	// Create API with setting engine
	api := webrtc.NewAPI(
		webrtc.WithSettingEngine(settingEngine),
	)

	return &webrtcManager{
		logf:                      c.logf,
		conn:                      c,
		peerConnectionsByEndpoint: make(map[*endpoint]*webrtcPeerState),
		peerConnectionsByDisco:    make(map[key.DiscoPublic]*webrtcPeerState),
		startConnectionCh:         make(chan *endpoint, 256),
		connectionReadyCh:         make(chan webrtcConnectionReadyEvent, 16),
		closeCh:                   make(chan struct{}),
		runLoopStoppedCh:          make(chan struct{}),
		api:                       api,
	}
}

func setOnError(dc *webrtc.DataChannel, fn func(error)) {
	// NO-OP... *webrtc.DataChannel does not have OnError for js.
}
