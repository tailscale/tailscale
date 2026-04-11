// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/pion/webrtc/v4"
	"tailscale.com/disco"
	"tailscale.com/types/key"
)

// dispatchPayload unmarshals a JSON-encoded signaling message received over
// disco and invokes dispatch with the sender's disco key. It is the shared body
// of the three kinds handled by [Manager.HandleSignal].
func (m *Manager) dispatchPayload[T any](kind disco.WebRTCSignalKind, fromDisco key.DiscoPublic, payload []byte, dispatch func(key.DiscoPublic, *T)) {
	var msg T
	if err := json.Unmarshal(payload, &msg); err != nil {
		m.logf("webrtc: disco: failed to unmarshal %s from %v: %v", kind, fromDisco.ShortString(), err)
		return
	}
	dispatch(fromDisco, &msg)
}

// HandleSignal implements magicsock.WebRTCManager. It unmarshals a WebRTC
// signaling message received over disco and dispatches it to the appropriate
// handler based on its kind.
func (m *Manager) HandleSignal(fromDisco key.DiscoPublic, kind disco.WebRTCSignalKind, payload []byte) {
	switch kind {
	case disco.WebRTCOffer:
		m.dispatchPayload(kind, fromDisco, payload, m.handleRemoteOffer)
	case disco.WebRTCAnswer:
		m.dispatchPayload(kind, fromDisco, payload, m.handleRemoteAnswer)
	case disco.WebRTCICECandidate:
		m.dispatchPayload(kind, fromDisco, payload, m.handleRemoteCandidate)
	default:
		m.logf("webrtc: disco: ignoring unknown signal kind %d from %v", kind, fromDisco.ShortString())
	}
}

// handleRemoteOffer processes an incoming offer from a peer.
func (m *Manager) handleRemoteOffer(remoteDisco key.DiscoPublic, offer *webrtc.SessionDescription) {
	// For incoming connections, we need to find the endpoint by disco key
	m.mu.Lock()
	ps, exists := m.peerConnectionsByDisco[remoteDisco]
	m.mu.Unlock()

	if exists {
		switch ps.peerConn.SignalingState() {
		case webrtc.SignalingStateHaveLocalOffer:
			// Glare: both sides sent offers simultaneously. Tiebreak by disco key:
			// the peer with the lexicographically smaller local key wins and keeps
			// its offer; the loser rolls back and answers the remote offer instead.
			localDisco := m.b.LocalDiscoKey()
			if localDisco.Compare(remoteDisco) < 0 {
				// We win — ignore their offer; they will roll back and answer ours.
				m.logf("webrtc: glare with peer %v: ignoring their offer (we win tiebreak)", remoteDisco.ShortString())
				return
			}
			// We lose — roll back our offer and fall through to answer theirs.
			m.logf("webrtc: glare with peer %v: rolling back our offer (we lose tiebreak)", remoteDisco.ShortString())
			if err := ps.peerConn.SetLocalDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeRollback}); err != nil {
				m.logf("webrtc: glare rollback failed: %v; closing and recreating", err)
				ps.peerConn.Close()
				m.mu.Lock()
				delete(m.peerConnectionsByPeer, ps.peer)
				delete(m.peerConnectionsByDisco, remoteDisco)
				m.mu.Unlock()
				exists = false
			}
		case webrtc.SignalingStateStable:
			if ps.state == stateConnected || ps.state == stateConnecting {
				// The connection is already working or in progress. Ignore the
				// peer's offer — they will notice their connection succeeded too
				// and stop retrying.
				m.logf("webrtc: ignoring offer from %v, already have %v connection", remoteDisco.ShortString(), ps.state)
				return
			}
			// Stable but in a terminal state (Failed/Closed): the peer is trying
			// to reconnect. Tear down our stale entry and answer fresh below.
			m.logf("webrtc: tearing down stale %v connection to %v, answering fresh offer", ps.state, remoteDisco.ShortString())
			ps.peerConn.Close()
			m.mu.Lock()
			delete(m.peerConnectionsByPeer, ps.peer)
			delete(m.peerConnectionsByDisco, remoteDisco)
			m.mu.Unlock()
			exists = false
		default:
			// Any other transitional signaling state — ignore, let it settle.
			m.logf("webrtc: ignoring offer from %v in unexpected signaling state %v", remoteDisco.ShortString(), ps.peerConn.SignalingState())
			return
		}
	}

	if !exists {
		var ok bool
		ps, ok = m.newAnswererConn(remoteDisco)
		if !ok {
			return
		}
	}

	if err := ps.peerConn.SetRemoteDescription(*offer); err != nil {
		m.logf("webrtc: failed to set remote description: %v", err)
		return
	}
	m.markRemoteDescSet(ps)

	// Create answer
	answer, err := ps.peerConn.CreateAnswer(nil)
	if err != nil {
		m.logf("webrtc: failed to create answer: %v", err)
		return
	}

	if err := ps.peerConn.SetLocalDescription(answer); err != nil {
		m.logf("webrtc: failed to set local description: %v", err)
		return
	}

	// Send answer via signaling
	if err := m.signaller.Answer(ps.localDisco.String(), remoteDisco.String(), &answer); err != nil {
		m.logf("webrtc: failed to send answer: %v", err)
		return
	}

	m.logf("webrtc: sent answer to peer %v", remoteDisco.ShortString())
}

// newAnswererConn creates the peerState for an incoming offer from a peer we
// don't yet have a connection with. It returns ok=false if the peer is unknown
// or the peer connection could not be created.
func (m *Manager) newAnswererConn(remoteDisco key.DiscoPublic) (*peerState, bool) {
	peer, ok := m.b.PeerForDisco(remoteDisco)
	if !ok {
		m.logf("webrtc: received offer from unknown peer %v with no endpoint", remoteDisco.ShortString())
		return nil, false
	}

	m.logf("webrtc: received offer from peer %v, creating answerer connection", remoteDisco.ShortString())

	peerConn, err := m.api.NewPeerConnection(iceConfig)
	if err != nil {
		m.logf("webrtc: failed to create peer connection for incoming offer: %v", err)
		return nil, false
	}

	ps := &peerState{
		peer:          peer,
		peerConn:      peerConn,
		localDisco:    m.b.LocalDiscoKey(),
		remoteDisco:   remoteDisco,
		remoteNodeKey: peer.NodeKey(),
		state:         stateConnecting,
	}

	m.mu.Lock()
	m.peerConnectionsByPeer[peer] = ps
	m.peerConnectionsByDisco[remoteDisco] = ps
	m.mu.Unlock()

	m.setupPeerConnHandlers(ps)

	// For the answerer, we wait for the data channel from the offerer.
	peerConn.OnDataChannel(func(dc *webrtc.DataChannel) {
		m.logf("webrtc: received data channel from peer %v", remoteDisco.ShortString())
		ps.dataChannel = dc
		m.setupDataChannel(ps, dc, remoteDisco, peer)
	})

	return ps, true
}

// handleRemoteAnswer processes an incoming answer from a peer.
func (m *Manager) handleRemoteAnswer(remoteDisco key.DiscoPublic, answer *webrtc.SessionDescription) {
	m.mu.Lock()
	ps, exists := m.peerConnectionsByDisco[remoteDisco]
	m.mu.Unlock()

	if !exists {
		m.logf("webrtc: received answer from unknown peer %v", remoteDisco.ShortString())
		return
	}

	if err := ps.peerConn.SetRemoteDescription(*answer); err != nil {
		m.logf("webrtc: failed to set remote description: %v", err)
		return
	}
	m.markRemoteDescSet(ps)

	m.logf("webrtc: set remote description for peer %v", remoteDisco.ShortString())
}

// handleRemoteCandidate processes an incoming ICE candidate from a peer.
func (m *Manager) handleRemoteCandidate(remoteDisco key.DiscoPublic, candidate *webrtc.ICECandidateInit) {
	m.mu.Lock()
	ps, exists := m.peerConnectionsByDisco[remoteDisco]
	if exists && !ps.remoteDescSet {
		// Remote description not set yet — buffer the candidate and apply it
		// once SetRemoteDescription is called (see markRemoteDescSet).
		if candidate.Candidate != "" {
			if addr := parseICECandidateAddr(candidate.Candidate); addr.IsValid() {
				ps.remoteAddr = addr
			}
		}
		ps.pendingCandidates = append(ps.pendingCandidates, *candidate)
		m.mu.Unlock()
		m.logf("webrtc: buffered ICE candidate for peer %v (remote desc not yet set)", remoteDisco.ShortString())
		return
	}
	m.mu.Unlock()

	if !exists {
		m.logf("webrtc: received candidate from unknown peer %v", remoteDisco.ShortString())
		return
	}

	// Try to extract the remote address from the candidate string
	// Candidate format: "candidate:... udp ... <ip> <port> typ ..."
	if candidate.Candidate != "" {
		if addr := parseICECandidateAddr(candidate.Candidate); addr.IsValid() {
			m.mu.Lock()
			ps.remoteAddr = addr
			m.mu.Unlock()
			m.logf("webrtc: peer %v candidate address: %v", remoteDisco.ShortString(), addr)
		}
	}

	if err := ps.peerConn.AddICECandidate(*candidate); err != nil {
		m.logf("webrtc: failed to add ICE candidate: %v", err)
		return
	}

	m.logf("webrtc: added ICE candidate for peer %v", remoteDisco.ShortString())
}

// markRemoteDescSet marks ps as having a remote description set and flushes
// any ICE candidates that arrived before SetRemoteDescription was called.
// Must be called after SetRemoteDescription succeeds, without holding m.mu.
func (m *Manager) markRemoteDescSet(ps *peerState) {
	m.mu.Lock()
	ps.remoteDescSet = true
	pending := ps.pendingCandidates
	ps.pendingCandidates = nil
	m.mu.Unlock()

	for i := range pending {
		if err := ps.peerConn.AddICECandidate(pending[i]); err != nil {
			m.logf("webrtc: failed to add buffered ICE candidate for peer %v: %v",
				ps.remoteDisco.ShortString(), err)
		}
	}
	if len(pending) > 0 {
		m.logf("webrtc: flushed %d buffered ICE candidates for peer %v",
			len(pending), ps.remoteDisco.ShortString())
	}
}

// handleLocalICECandidate sends a local ICE candidate to a peer via signaling.
func (m *Manager) handleLocalICECandidate(ps *peerState, candidate *webrtc.ICECandidate) {
	candidateInit := candidate.ToJSON()
	if err := m.signaller.Candidate(ps.localDisco.String(), ps.remoteDisco.String(), &candidateInit); err != nil {
		m.logf("webrtc: failed to send candidate: %v", err)
		return
	}

	m.logf("webrtc: sent ICE candidate to peer %v", ps.remoteDisco.ShortString())
}

// parseICECandidateAddr extracts the IP:port from an ICE candidate SDP string.
// Example candidate: "candidate:1234 1 udp 2130706431 192.168.1.100 54321 typ host"
func parseICECandidateAddr(candidate string) netip.AddrPort {
	fields := strings.Fields(candidate)
	// Format: candidate:<foundation> <component> <protocol> <priority> <ip> <port> typ <type>
	if len(fields) < 7 {
		return netip.AddrPort{}
	}

	ip := fields[4]
	port := fields[5]

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.AddrPort{}
	}

	var portNum uint16
	if _, err := fmt.Sscanf(port, "%d", &portNum); err != nil {
		return netip.AddrPort{}
	}

	return netip.AddrPortFrom(addr, portNum)
}
