// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package webrtc

import (
	"net"
	"runtime"
	"strconv"

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

	// Create and send the offer on a separate goroutine, NOT on the runLoop.
	// CreateOffer/SetLocalDescription are blocking calls into the browser's
	// async RTCPeerConnection on wasm. During glare (both peers offer at once),
	// an incoming offer handled on another goroutine can Close() this peerConn
	// mid-call; doing that work on the runLoop would wedge it permanently
	// (no more retries, no new connections). ps and ps.peerConn are already
	// published to the maps above, so the glare handler can see and tear down
	// this attempt safely while this goroutine unblocks or errors out on its
	// own. sendOffer runs after SetLocalDescription, so a returning answer
	// always finds our local description set.
	go m.createAndSendOffer(ps, peerConn, remoteDisco, p)
}

// createAndSendOffer performs the blocking offer setup off the runLoop. See
// handleStartConnection for why this must not run on the runLoop.
func (m *manager) createAndSendOffer(ps *peerState, peerConn *webrtc.PeerConnection, remoteDisco key.DiscoPublic, p magicsock.WebRTCPeer) {
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

	if err := m.sendOffer(remoteDisco, &offer); err != nil {
		m.logf("webrtc: failed to send offer: %v", err)
		peerConn.Close()
		m.mu.Lock()
		// Only delete if this attempt still owns the map slot; a concurrent
		// glare rebuild may have replaced it with an answerer conn.
		if cur, ok := m.peerConnectionsByPeer[p]; ok && cur == ps {
			delete(m.peerConnectionsByPeer, p)
			delete(m.peerConnectionsByDisco, remoteDisco)
		}
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
// detaches for the zero-allocation reader path (falling back to OnMessage), then
// marks the WebRTC path ready so magicsock can probe and select it.
func (m *manager) setupDataChannel(ps *peerState, dc *webrtc.DataChannel, remoteDisco key.DiscoPublic, p magicsock.WebRTCPeer) {
	dc.OnError(func(err error) {
		m.logf("webrtc: data channel error for peer %v: %v", remoteDisco.ShortString(), err)
	})

	dc.OnOpen(func() {
		// DetachDataChannels is enabled, so get a raw io.ReadWriteCloser and
		// spin a dedicated reader goroutine (zero per-message allocations). If
		// detaching isn't available, fall back to OnMessage callbacks.
		if rwc, err := dc.Detach(); err == nil {
			ps.dcRW.Store(&dataChannelRW{rwc})
			go m.runDataChannelReader(ps, rwc)
		} else {
			m.logf("webrtc: data channel detach failed for peer %v, using OnMessage: %v",
				remoteDisco.ShortString(), err)
			dc.OnMessage(func(msg webrtc.DataChannelMessage) {
				m.deliverMsg(ps, msg.Data)
			})
		}
		m.logf("webrtc: data channel opened for peer %v", remoteDisco.ShortString())

		// Mark the WebRTC path ready directly from this pion callback goroutine.
		// We deliberately do NOT hop through the runLoop: the runLoop can be
		// busy (e.g. blocked in a pion CreateOffer during glare) while this
		// side's answerer channel is already open, and routing readiness through
		// it would strand the path on DERP. SetWebRTCChannelReady only takes the
		// endpoint lock, not m.mu, so it's safe to call here.
		if m.b.DisableWebRTC() {
			return
		}
		p.SetWebRTCChannelReady(true)
		m.logf("webrtc: marked WebRTC channel ready for peer %v", remoteDisco.ShortString())
	})
}

// handleConnectionStateChange handles WebRTC connection state changes.
func (m *manager) handleConnectionStateChange(ps *peerState, state webrtc.PeerConnectionState) {
	m.logf("webrtc: connection state changed to %s for peer %v", state.String(), ps.remoteDisco.ShortString())

	m.mu.Lock()

	var channelDown bool
	switch state {
	case webrtc.PeerConnectionStateConnected:
		ps.state = stateConnected
		// Record and log the selected ICE candidate pair. This is the path ICE
		// actually chose (LAN host vs. STUN server-reflexive vs. relay), and is
		// the authoritative source for the remote address we report in status.
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

			// Report the selected remote candidate as the peer's WebRTC address.
			// This is a display string: cp.Remote.Address may be a numeric IP or
			// an mDNS ".local" name (browsers hide LAN IPs behind these), and we
			// surface either as-is.
			m.mu.Lock()
			ps.remoteAddr = net.JoinHostPort(cp.Remote.Address, strconv.Itoa(int(cp.Remote.Port)))
			m.mu.Unlock()
		}()
	case webrtc.PeerConnectionStateFailed:
		ps.state = stateFailed
		ps.dcRW.Store(nil)
		channelDown = true
	case webrtc.PeerConnectionStateClosed:
		ps.state = stateClosed
		ps.dcRW.Store(nil)
		channelDown = true
	case webrtc.PeerConnectionStateDisconnected:
		// Recoverable in principle; nothing to do. WebRTC liveness is driven by
		// disco heartbeat pongs, so when traffic stops flowing the trust window
		// lapses (~6.5s) and magicsock falls back to DERP. bestAddr is left to
		// the disco machinery rather than demoted on this pion state edge, which
		// keeps the two sides in agreement.
	}

	m.mu.Unlock()

	// SetWebRTCChannelReady acquires the endpoint lock; call it without m.mu
	// held. Clearing the ready flag stops the heartbeat re-probing a dead path.
	if channelDown {
		ps.peer.SetWebRTCChannelReady(false)
	}
}
