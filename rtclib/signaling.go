// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rtclib

import "github.com/pion/webrtc/v4"

// Signaling message types.
const (
	MessageTypeOffer     = "offer"
	MessageTypeAnswer    = "answer"
	MessageTypeCandidate = "candidate"
)

// SignalingMessage represents a message exchanged over the signaling channel.
type SignalingMessage struct {
	Type      string                     `json:"type"` // "offer", "answer", "candidate"
	From      string                     `json:"from"` // sender's disco public key (hex)
	To        string                     `json:"to"`   // recipient's disco public key (hex)
	Offer     *webrtc.SessionDescription `json:"offer,omitempty"`
	Answer    *webrtc.SessionDescription `json:"answer,omitempty"`
	Candidate *webrtc.ICECandidateInit   `json:"candidate,omitempty"`
}

// SignalHandler defines callbacks for handling incoming signaling messages.
type SignalHandler interface {
	// HandleOffer is called when an offer is received from a peer.
	HandleOffer(from, to string, offer *webrtc.SessionDescription)

	// HandleAnswer is called when an answer is received from a peer.
	HandleAnswer(from, to string, answer *webrtc.SessionDescription)

	// HandleCandidate is called when an ICE candidate is received from a peer.
	HandleCandidate(from, to string, candidate *webrtc.ICECandidateInit)
}

// Signaller defines the interface for WebRTC signaling implementations.
type Signaller interface {
	// Start begins the signaling connection with the provided handler.
	Start(handler SignalHandler) error

	// Offer sends an SDP offer to a peer.
	Offer(from, to string, offer *webrtc.SessionDescription) error

	// Answer sends an SDP answer to a peer.
	Answer(from, to string, answer *webrtc.SessionDescription) error

	// Candidate sends an ICE candidate to a peer.
	Candidate(from, to string, candidate *webrtc.ICECandidateInit) error

	// Close shuts down the signaling connection.
	Close() error
}
