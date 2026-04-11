// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"encoding/json"
	"fmt"

	"github.com/pion/webrtc/v4"
	"tailscale.com/disco"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
)

// discoSignaller implements signaller by routing WebRTC signaling
// messages through the existing Tailscale disco/DERP infrastructure. This
// eliminates the need for an external signaling server: SDP offers/answers and
// ICE candidates travel as encrypted disco messages relayed over DERP, using
// the same authenticated peer-to-peer path that Tailscale already maintains.
//
// Sending is delegated to the magicsock [magicsock.WebRTCBackend]; receiving
// happens in magicsock's disco dispatch, which calls [manager.HandleSignal].
type discoSignaller struct {
	b magicsock.WebRTCBackend
}

// Ensure discoSignaller implements signaller.
var _ signaller = (*discoSignaller)(nil)

// Start implements signaller. There is nothing to start: the disco/DERP path
// is managed by the surrounding Conn.
func (ds *discoSignaller) Start() error { return nil }

// Close implements signaller. Nothing to tear down; the disco/DERP
// path is managed by the surrounding Conn.
func (ds *discoSignaller) Close() error { return nil }

// Offer implements signaller.
func (ds *discoSignaller) Offer(from, to string, offer *webrtc.SessionDescription) error {
	return ds.marshalAndSend(disco.WebRTCOffer, to, offer)
}

// Answer implements signaller.
func (ds *discoSignaller) Answer(from, to string, answer *webrtc.SessionDescription) error {
	return ds.marshalAndSend(disco.WebRTCAnswer, to, answer)
}

// Candidate implements signaller.
func (ds *discoSignaller) Candidate(from, to string, candidate *webrtc.ICECandidateInit) error {
	return ds.marshalAndSend(disco.WebRTCICECandidate, to, candidate)
}

// marshalAndSend JSON-encodes msg and sends it to the toDisco peer as a
// [disco.WebRTCSignal] of the given kind. It is the shared body of the three
// signaller send methods, which differ only in msg's type and the kind.
func (ds *discoSignaller) marshalAndSend[T any](kind disco.WebRTCSignalKind, toDisco string, msg *T) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("webrtc disco signaller: marshal %s: %w", kind, err)
	}
	return ds.send(toDisco, &disco.WebRTCSignal{Kind: kind, Payload: payload})
}

// send routes a disco WebRTC message to the peer identified by toDisco (a hex
// disco public key string), via the magicsock backend.
func (ds *discoSignaller) send(toDisco string, m disco.Message) error {
	var toKey key.DiscoPublic
	if err := toKey.UnmarshalText([]byte(toDisco)); err != nil {
		return fmt.Errorf("webrtc disco signaller: parse disco key %q: %w", toDisco, err)
	}
	return ds.b.SendSignal(toKey, m)
}
