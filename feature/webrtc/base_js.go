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
	settingEngine := webrtc.SettingEngine{}

	// Unlike native (base_native.go) we deliberately do NOT enable
	// DetachDataChannels here. In the browser, pion's detached reader
	// (datachannel_js_detach.go) is just a wrapper that installs
	// dc.OnMessage(func(msg){ read <- msg }) on an unbuffered channel, so vs.
	// calling OnMessage directly (as setupDataChannel does) it only adds a
	// goroutine hop per message with no zero-copy win. We keep the manual
	// OnMessage path.
	//
	// settingEngine.DetachDataChannels()

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
		closeCh:                make(chan struct{}),
		runLoopStoppedCh:       make(chan struct{}),
		api:                    api,
	}
}
