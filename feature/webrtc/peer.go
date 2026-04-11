// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"io"
	"sync/atomic"

	"github.com/pion/webrtc/v4"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
)

// connState represents the state of a WebRTC connection.
type connState int

const (
	stateIdle connState = iota
	stateConnecting
	stateConnected
	stateFailed
	stateClosed
)

func (s connState) String() string {
	switch s {
	case stateIdle:
		return "idle"
	case stateConnecting:
		return "connecting"
	case stateConnected:
		return "connected"
	case stateFailed:
		return "failed"
	case stateClosed:
		return "closed"
	}
	return "unknown"
}

// dataChannelRW is the detached io.ReadWriteCloser for a WebRTC DataChannel.
// It is stored via atomic.Pointer so the hot send path can retrieve it without
// holding the manager mutex.
type dataChannelRW struct {
	io.ReadWriteCloser
}

// peerState tracks WebRTC connection state for a single peer.
type peerState struct {
	peer          magicsock.WebRTCPeer
	peerConn      *webrtc.PeerConnection
	dataChannel   *webrtc.DataChannel
	dcRW          atomic.Pointer[dataChannelRW] // non-nil once the DataChannel is open
	remoteDisco   key.DiscoPublic
	remoteNodeKey key.NodePublic // peer's node public key (for WireGuard)
	remoteAddr    string         // selected remote ICE candidate "host:port"; may be an mDNS ".local" name
	state         connState

	// remoteDescSet is true once SetRemoteDescription has been called.
	// ICE candidates that arrive before that point are held in
	// pendingCandidates and applied immediately after. Both fields are
	// protected by manager.mu.
	remoteDescSet     bool
	pendingCandidates []webrtc.ICECandidateInit
}

// connectionReadyEvent signals that a WebRTC connection is ready.
type connectionReadyEvent struct {
	remoteDisco key.DiscoPublic
	peer        magicsock.WebRTCPeer
}
