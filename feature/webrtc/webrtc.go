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

// BatchMagic is the first byte of a batched WebRTC SCTP message.
// WireGuard packets start with 0x01–0x04, disco packets start with 0x54 ('T'),
// so 0xBA is unambiguous. It must match magicsock's webRTCBatchMagic so the
// send path frames batches identically.
const BatchMagic = byte(0xBA)

// Manager manages WebRTC connections for magicsock.
type Manager struct {
	logf logger.Logf
	b    magicsock.WebRTCBackend

	mu                     sync.RWMutex
	peerConnectionsByPeer  map[magicsock.WebRTCPeer]*peerState
	peerConnectionsByDisco map[key.DiscoPublic]*peerState

	signaller Signaller

	// Control channels
	startConnectionCh chan magicsock.WebRTCPeer
	connectionReadyCh chan connectionReadyEvent
	closeCh           chan struct{}
	runLoopStoppedCh  chan struct{}

	// WebRTC API configuration
	api *webrtc.API
}

// NewManager creates a new WebRTC manager using disco-based signaling, or nil
// if it fails to initialize.
func NewManager(b magicsock.WebRTCBackend) *Manager {
	m := newManagerBase(b)

	m.signaller = &discoSignaller{b: b}
	if err := m.signaller.Start(); err != nil {
		m.logf("webrtc: failed to start signaller: %v", err)
		return nil
	}

	go m.runLoop()

	return m
}

// Close shuts down the WebRTC manager.
func (m *Manager) Close() error {
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

	return nil
}

// runLoop is the main event loop for the WebRTC manager.
func (m *Manager) runLoop() {
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
