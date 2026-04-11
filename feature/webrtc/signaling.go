// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import "github.com/pion/webrtc/v4"

// signaller defines the interface for sending WebRTC signaling messages to a
// peer. Incoming messages are delivered separately, via
// [manager.HandleSignal], rather than through this interface.
type signaller interface {
	// Start begins the signaling connection.
	Start() error

	// Offer sends an SDP offer to a peer.
	Offer(from, to string, offer *webrtc.SessionDescription) error

	// Answer sends an SDP answer to a peer.
	Answer(from, to string, answer *webrtc.SessionDescription) error

	// Candidate sends an ICE candidate to a peer.
	Candidate(from, to string, candidate *webrtc.ICECandidateInit) error

	// Close shuts down the signaling connection.
	Close() error
}
