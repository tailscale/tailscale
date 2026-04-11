// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package webrtc implements the experimental WebRTC connectivity path for
// magicsock. It registers itself with magicsock from its init via
// [magicsock.HookNewWebRTCManager], so magicsock has no compile-time
// dependency on pion/WebRTC; the pion dependency is linked in only when this
// package is imported.
//
// The package reaches magicsock through the [magicsock.WebRTCBackend] and
// [magicsock.WebRTCPeer] interfaces (one peer per endpoint), giving it the
// minimal set of capabilities it needs (send disco signaling, deliver received
// packets, and mutate a peer's best path) without exposing magicsock
// internals.
package webrtc

import (
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/magicsock"
)

// manager manages WebRTC connections for magicsock.
type manager struct {
	logf logger.Logf
	b    magicsock.WebRTCBackend

	mu                     sync.RWMutex
	peerConnectionsByPeer  map[magicsock.WebRTCPeer]*peerState
	peerConnectionsByDisco map[key.DiscoPublic]*peerState

	signaller signaller

	// Control channels
	startConnectionCh chan magicsock.WebRTCPeer
	connectionReadyCh chan connectionReadyEvent
	closeCh           chan struct{}
	runLoopStoppedCh  chan struct{}
	closeOnce         sync.Once

	// WebRTC API configuration
	api *webrtc.API
}

// newManager is the [magicsock.HookNewWebRTCManager] implementation. It creates
// a WebRTC manager using disco-based signaling and returns it as a
// [magicsock.WebRTCManager]. On failure it returns an untyped nil interface
// (not a typed nil *manager) so magicsock's nil check behaves correctly.
func newManager(b magicsock.WebRTCBackend) magicsock.WebRTCManager {
	m := newManagerBase(b)

	m.signaller = &discoSignaller{b: b}
	if err := m.signaller.Start(); err != nil {
		m.logf("webrtc: failed to start signaller: %v", err)
		return nil
	}

	go m.runLoop()

	return m
}

// Close shuts down the WebRTC manager. It is idempotent and safe to call more
// than once (Conn.Close may run multiple times).
func (m *manager) Close() error {
	m.closeOnce.Do(func() {
		// Close signaller first to stop new messages
		if m.signaller != nil {
			if err := m.signaller.Close(); err != nil {
				m.logf("webrtc: signaller close error: %v", err)
			}
		}

		// Signal runLoop to stop
		close(m.closeCh)

		// Wait for runLoop to finish with timeout
		select {
		case <-m.runLoopStoppedCh:
		case <-time.After(2 * time.Second):
			m.logf("webrtc: close timed out, forcing shutdown")
		}

		m.mu.Lock()
		defer m.mu.Unlock()

		// Close all peer connections
		for _, ps := range m.peerConnectionsByPeer {
			if ps.peerConn != nil {
				ps.peerConn.Close()
			}
		}
		m.peerConnectionsByPeer = nil
		m.peerConnectionsByDisco = nil
	})
	return nil
}

// runLoop is the main event loop for the WebRTC manager.
func (m *manager) runLoop() {
	defer close(m.runLoopStoppedCh)

	retryTicker := time.NewTicker(15 * time.Second)
	defer retryTicker.Stop()

	for {
		select {
		case p := <-m.startConnectionCh:
			m.handleStartConnection(p)

		case event := <-m.connectionReadyCh:
			m.handleConnectionReady(event)

		case <-retryTicker.C:
			m.retryFailedConnections()

		case <-m.closeCh:
			return
		}
	}
}
