// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/pion/webrtc/v4"
	"tailscale.com/disco"
	"tailscale.com/rtclib"
	"tailscale.com/types/key"
)

// discoSignaller implements rtclib.Signaller by routing WebRTC signaling
// messages through the existing Tailscale disco/DERP infrastructure. This
// eliminates the need for an external signaling server: SDP offers/answers and
// ICE candidates travel as encrypted disco messages relayed over DERP, using
// the same authenticated peer-to-peer path that Tailscale already maintains.
type discoSignaller struct {
	conn    *Conn
	handler rtclib.SignalHandler
}

// Ensure discoSignaller implements rtclib.Signaller.
var _ rtclib.Signaller = (*discoSignaller)(nil)

// Start implements rtclib.Signaller.
func (ds *discoSignaller) Start(handler rtclib.SignalHandler) error {
	ds.handler = handler
	return nil
}

// Close implements rtclib.Signaller. Nothing to tear down — the disco/DERP
// path is managed by the surrounding Conn.
func (ds *discoSignaller) Close() error { return nil }

// Offer implements rtclib.Signaller.
func (ds *discoSignaller) Offer(from, to string, offer *webrtc.SessionDescription) error {
	payload, err := json.Marshal(offer)
	if err != nil {
		return fmt.Errorf("webrtc disco signaller: marshal offer: %w", err)
	}
	return ds.send(to, &disco.WebRTCOffer{Payload: payload})
}

// Answer implements rtclib.Signaller.
func (ds *discoSignaller) Answer(from, to string, answer *webrtc.SessionDescription) error {
	payload, err := json.Marshal(answer)
	if err != nil {
		return fmt.Errorf("webrtc disco signaller: marshal answer: %w", err)
	}
	return ds.send(to, &disco.WebRTCAnswer{Payload: payload})
}

// Candidate implements rtclib.Signaller.
func (ds *discoSignaller) Candidate(from, to string, candidate *webrtc.ICECandidateInit) error {
	payload, err := json.Marshal(candidate)
	if err != nil {
		return fmt.Errorf("webrtc disco signaller: marshal candidate: %w", err)
	}
	return ds.send(to, &disco.WebRTCICECandidate{Payload: payload})
}

// send routes a disco WebRTC message to the peer identified by toDisco (a hex
// disco public key string), via that peer's home DERP region.
func (ds *discoSignaller) send(toDisco string, m disco.Message) error {
	var toKey key.DiscoPublic
	if err := toKey.UnmarshalText([]byte(toDisco)); err != nil {
		return fmt.Errorf("webrtc disco signaller: parse disco key %q: %w", toDisco, err)
	}

	// Find the endpoint and its home DERP address under the Conn lock.
	ds.conn.mu.Lock()
	var (
		derpAddr netip.AddrPort
		nodeKey  key.NodePublic
		found    bool
	)
	ds.conn.peerMap.forEachEndpointWithDiscoKey(toKey, func(ep *endpoint) bool {
		ep.mu.Lock()
		derpAddr = ep.derpAddr
		ep.mu.Unlock()
		nodeKey = ep.publicKey
		found = true
		return false // stop after first match
	})
	ds.conn.mu.Unlock()

	if !found {
		return fmt.Errorf("webrtc disco signaller: no endpoint for disco key %v", toKey.ShortString())
	}
	if !derpAddr.IsValid() {
		return fmt.Errorf("webrtc disco signaller: no DERP address for peer %v", toKey.ShortString())
	}

	_, err := ds.conn.sendDiscoMessage(epAddr{ap: derpAddr}, nodeKey, toKey, m, discoLog)
	return err
}
