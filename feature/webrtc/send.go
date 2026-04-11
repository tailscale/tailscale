// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

// This file implements the send side of WebRTC signaling: offers, answers, and
// ICE candidates are JSON-encoded and sent to the peer as disco messages over
// DERP (via the magicsock backend). Incoming messages arrive separately,
// through magicsock's disco dispatch into [manager.HandleSignal].

import (
	"encoding/json"
	"fmt"

	"github.com/pion/webrtc/v4"
	"tailscale.com/disco"
	"tailscale.com/types/key"
)

// sendOffer sends an SDP offer to the peer with the given disco key.
func (m *manager) sendOffer(to key.DiscoPublic, offer *webrtc.SessionDescription) error {
	return sendSignal(m, disco.WebRTCOffer, to, offer)
}

// sendAnswer sends an SDP answer to the peer with the given disco key.
func (m *manager) sendAnswer(to key.DiscoPublic, answer *webrtc.SessionDescription) error {
	return sendSignal(m, disco.WebRTCAnswer, to, answer)
}

// sendCandidate sends an ICE candidate to the peer with the given disco key.
func (m *manager) sendCandidate(to key.DiscoPublic, candidate *webrtc.ICECandidateInit) error {
	return sendSignal(m, disco.WebRTCICECandidate, to, candidate)
}

// sendSignal JSON-encodes msg and sends it to the peer as a [disco.WebRTCSignal]
// of the given kind. It is the shared body of the three send methods above,
// which differ only in msg's type and the kind.
func sendSignal[T any](m *manager, kind disco.WebRTCSignalKind, to key.DiscoPublic, msg *T) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("webrtc: marshal %s: %w", kind, err)
	}
	return m.b.SendSignal(to, &disco.WebRTCSignal{Kind: kind, Payload: payload})
}
