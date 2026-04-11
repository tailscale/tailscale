// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"runtime"

	"github.com/pion/webrtc/v4"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/magicsock"
)

// iceConfig is the pion configuration used for every peer connection.
var iceConfig = webrtc.Configuration{
	ICEServers: []webrtc.ICEServer{
		// We deliberately do not configure any TURN relays; DERP is our relay fallback.
		// FIXME(adrianosela): run our own STUN? can we plug this into DERP's flavor of STUN?
		{URLs: []string{"stun:stun.l.google.com:19302"}},
	},
	ICETransportPolicy: webrtc.ICETransportPolicyAll,
}

// startConnection initiates a WebRTC connection to a peer.
func (m *manager) startConnection(p magicsock.WebRTCPeer) {
	if m.b.DisableWebRTC() {
		return
	}
	// WebRTC is only worthwhile when at least one side is a browser/Wasm ("js")
	// node, which cannot use direct UDP. Between two native peers, direct UDP
	// or DERP already covers connectivity, so skip the WebRTC machinery
	// entirely.
	if runtime.GOOS != "js" && !p.IsJS() {
		return
	}
	select {
	case m.startConnectionCh <- p:
	case <-m.closeCh:
	default:
		m.logf("webrtc: startConnection queue full for %v", p.NodeAddr())
	}
}

// EnsureConnecting triggers a WebRTC connection to p if one is not already in
// progress or established. It also retries connections in terminal states
// (Failed, Closed). It is safe to call from the hot send path.
func (m *manager) EnsureConnecting(p magicsock.WebRTCPeer) {
	m.mu.RLock()
	ps, exists := m.peerConnectionsByPeer[p]
	needConnect := !exists || ps.state == stateFailed || ps.state == stateClosed
	m.mu.RUnlock()
	if needConnect {
		m.startConnection(p)
	}
}

// retryFailedConnections re-queues any connections in a terminal state so they
// get a fresh attempt. This covers cases where both peers restart simultaneously
// and the initial attempt fails before DERP is established.
func (m *manager) retryFailedConnections() {
	m.mu.RLock()
	var toRetry []magicsock.WebRTCPeer
	for p, ps := range m.peerConnectionsByPeer {
		if ps.state == stateFailed || ps.state == stateClosed {
			toRetry = append(toRetry, p)
		}
	}
	m.mu.RUnlock()

	for _, p := range toRetry {
		m.logf("webrtc: retrying failed connection to peer %v", p.NodeAddr())
		m.startConnection(p)
	}
}

// handleStartConnection creates a new WebRTC connection to a peer.
func (m *manager) handleStartConnection(p magicsock.WebRTCPeer) {
	m.mu.Lock()

	// Check if we already have a connection
	if ps, exists := m.peerConnectionsByPeer[p]; exists {
		switch ps.state {
		case stateConnecting, stateConnected:
			m.mu.Unlock()
			return
		default:
			// Terminal state (Failed, Closed): close the old connection and
			// remove it from the maps so we can create a fresh one below.
			ps.peerConn.Close()
			delete(m.peerConnectionsByPeer, p)
			delete(m.peerConnectionsByDisco, ps.remoteDisco)
		}
	}

	remoteDisco, ok := p.DiscoKey()
	if !ok {
		m.mu.Unlock()
		m.logf("webrtc: cannot start connection, peer has no disco key")
		return
	}

	// Check that the peer's DERP address is known before proceeding.
	// If it isn't, the signaling offer will fail immediately. This can
	// happen on startup or after a disco-key rotation before the DERP
	// connection to the new key is established. The next netmap update
	// will re-trigger startConnection once the peer is reachable.
	if !p.DERPReady() {
		m.mu.Unlock()
		return
	}

	m.logf("webrtc: starting connection to peer %v (disco %v)", p.NodeAddr(), remoteDisco.ShortString())

	m.mu.Unlock()

	peerConn, err := m.api.NewPeerConnection(iceConfig)
	if err != nil {
		m.logf("webrtc: failed to create peer connection: %v", err)
		return
	}

	ps := &peerState{
		peer:          p,
		peerConn:      peerConn,
		remoteDisco:   remoteDisco,
		remoteNodeKey: p.NodeKey(),
		state:         stateConnecting,
	}

	// Store peer state
	m.mu.Lock()
	m.peerConnectionsByPeer[p] = ps
	m.peerConnectionsByDisco[remoteDisco] = ps
	m.mu.Unlock()

	m.setupPeerConnHandlers(ps)

	// Create an unordered, unreliable data channel (MaxRetransmits=0).
	// WireGuard is designed to run over raw UDP, which is unordered and
	// unreliable. Using an ordered/reliable DataChannel (the default) wraps
	// WireGuard in SCTP's reliable-ordered-stream semantics, causing
	// head-of-line blocking whenever a packet is lost: SCTP holds back all
	// subsequent packets until the missing one is retransmitted and delivered
	// in order. That is why throughput over WebRTC was worse than DERP.
	// Setting Ordered=false and MaxRetransmits=0 makes the DataChannel behave
	// like a UDP socket, which is exactly what WireGuard expects.
	ordered := false
	maxRetransmits := uint16(0)
	dataChannel, err := peerConn.CreateDataChannel("tailscale-wg", &webrtc.DataChannelInit{
		Ordered:        &ordered,
		MaxRetransmits: &maxRetransmits,
	})
	if err != nil {
		m.logf("webrtc: failed to create data channel: %v", err)
		peerConn.Close()
		return
	}

	ps.dataChannel = dataChannel
	m.setupDataChannel(ps, dataChannel, remoteDisco, p)

	// Create and send offer
	offer, err := peerConn.CreateOffer(nil)
	if err != nil {
		m.logf("webrtc: failed to create offer: %v", err)
		peerConn.Close()
		return
	}

	if err := peerConn.SetLocalDescription(offer); err != nil {
		m.logf("webrtc: failed to set local description: %v", err)
		peerConn.Close()
		return
	}

	// Send offer via signaling
	if err := m.sendOffer(remoteDisco, &offer); err != nil {
		m.logf("webrtc: failed to send offer: %v", err)
		peerConn.Close()
		m.mu.Lock()
		delete(m.peerConnectionsByPeer, p)
		delete(m.peerConnectionsByDisco, remoteDisco)
		m.mu.Unlock()
		return
	}

	m.logf("webrtc: sent offer to peer %v", remoteDisco.ShortString())
}

// setupPeerConnHandlers wires the connection-state and ICE-candidate callbacks
// shared by the offerer and answerer paths.
func (m *manager) setupPeerConnHandlers(ps *peerState) {
	ps.peerConn.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		m.handleConnectionStateChange(ps, state)
	})
	ps.peerConn.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil {
			m.handleLocalICECandidate(ps, candidate)
		}
	})
}

// setupDataChannel wires the handlers for a DataChannel (the offerer's
// self-created channel or the answerer's received channel). When it opens, it
// detaches for the zero-allocation native reader path, or falls back to
// OnMessage in the browser, then signals the connection is ready.
func (m *manager) setupDataChannel(ps *peerState, dc *webrtc.DataChannel, remoteDisco key.DiscoPublic, p magicsock.WebRTCPeer) {
	dc.OnError(func(err error) {
		m.logf("webrtc: data channel error for peer %v: %v", remoteDisco.ShortString(), err)
	})

	dc.OnOpen(func() {
		// Native: DetachDataChannels was enabled; get a raw io.ReadWriteCloser
		// and spin a dedicated reader goroutine (zero per-message allocations).
		// JS/fallback: Detach() returns an error; fall back to OnMessage
		// callbacks, which is the only API available in the browser.
		if rwc, err := dc.Detach(); err == nil {
			ps.dcRW.Store(&dataChannelRW{rwc})
			go m.runDataChannelReader(ps, rwc)
		} else {
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				m.deliverMsg(ps, msg.Data)
			})
		}
		m.logf("webrtc: data channel opened for peer %v", remoteDisco.ShortString())
		// This runs on a pion callback goroutine. Select on closeCh so we don't
		// block forever if runLoop has already stopped (nothing would drain the
		// channel then).
		select {
		case m.connectionReadyCh <- connectionReadyEvent{remoteDisco: remoteDisco, peer: p}:
		case <-m.closeCh:
		}
	})
}

// handleConnectionStateChange handles WebRTC connection state changes.
func (m *manager) handleConnectionStateChange(ps *peerState, state webrtc.PeerConnectionState) {
	m.logf("webrtc: connection state changed to %s for peer %v", state.String(), ps.remoteDisco.ShortString())

	m.mu.Lock()

	var clearBestAddr bool
	switch state {
	case webrtc.PeerConnectionStateConnected:
		ps.state = stateConnected
		// Log the selected ICE candidate pair so we can confirm the actual
		// data path (LAN host candidate vs. STUN server-reflexive vs. relay).
		go func() {
			cp, err := ps.peerConn.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
			if err != nil || cp == nil {
				m.logf("webrtc: peer %v connected (selected candidate pair unavailable: %v)",
					ps.remoteDisco.ShortString(), err)
				return
			}
			m.logf("webrtc: peer %v connected via %s:%d → %s:%d (local %s, remote %s)",
				ps.remoteDisco.ShortString(),
				cp.Local.Address, cp.Local.Port,
				cp.Remote.Address, cp.Remote.Port,
				cp.Local.Typ, cp.Remote.Typ)
		}()
	case webrtc.PeerConnectionStateFailed:
		ps.state = stateFailed
		ps.dcRW.Store(nil)
		clearBestAddr = true
	case webrtc.PeerConnectionStateClosed:
		ps.state = stateClosed
		ps.dcRW.Store(nil)
		clearBestAddr = true
	case webrtc.PeerConnectionStateDisconnected:
		// Transient state; do not clear bestAddr yet; the connection may recover.
	}

	m.mu.Unlock()

	// ClearWebRTCPath acquires the endpoint lock; must be called without m.mu held.
	if clearBestAddr {
		ps.peer.ClearWebRTCPath()
		m.logf("webrtc: cleared WebRTC bestAddr for peer %v, falling back to DERP", ps.remoteDisco.ShortString())
	}
}

// handleConnectionReady marks a WebRTC connection as ready and updates the peer.
func (m *manager) handleConnectionReady(event connectionReadyEvent) {
	m.logf("webrtc: connection ready for peer %v", event.remoteDisco.ShortString())
	if m.b.DisableWebRTC() {
		return
	}

	// Update the peer's best path to use WebRTC.
	event.peer.SetWebRTCPath()
	m.logf("webrtc: updated endpoint %v with WebRTC path", event.peer.NodeAddr())
}
