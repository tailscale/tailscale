// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/rtclib"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// webrtcConnState represents the state of a WebRTC connection.
type webrtcConnState int

const (
	webrtcStateIdle webrtcConnState = iota
	webrtcStateConnecting
	webrtcStateConnected
	webrtcStateFailed
	webrtcStateClosed
)

// dataChannelRW is the detached io.ReadWriteCloser for a WebRTC DataChannel.
// It is stored via atomic.Pointer so the hot send path can retrieve it without
// holding the webrtcManager mutex.
type dataChannelRW struct {
	io.ReadWriteCloser
}

// webrtcPeerState tracks WebRTC connection state for a single peer.
type webrtcPeerState struct {
	ep            *endpoint
	peerConn      *webrtc.PeerConnection
	dataChannel   *webrtc.DataChannel
	dcRW          atomic.Pointer[dataChannelRW] // non-nil once the DataChannel is open
	localDisco    key.DiscoPublic
	remoteDisco   key.DiscoPublic
	remoteNodeKey key.NodePublic // peer's node public key (for WireGuard)
	remoteAddr    netip.AddrPort // actual remote address from ICE candidate
	state         webrtcConnState
	lastError     error
	createdAt     time.Time

	// remoteDescSet is true once SetRemoteDescription has been called.
	// ICE candidates that arrive before that point are held in
	// pendingCandidates and applied immediately after. Both fields are
	// protected by webrtcManager.mu.
	remoteDescSet    bool
	pendingCandidates []webrtc.ICECandidateInit
}

// webrtcConnectionReadyEvent signals that a WebRTC connection is ready.
type webrtcConnectionReadyEvent struct {
	remoteDisco key.DiscoPublic
	ep          *endpoint
}

// webrtcManager manages WebRTC connections for magicsock.
type webrtcManager struct {
	logf logger.Logf
	conn *Conn // parent magicsock.Conn

	mu                        sync.RWMutex
	peerConnectionsByEndpoint map[*endpoint]*webrtcPeerState
	peerConnectionsByDisco    map[key.DiscoPublic]*webrtcPeerState

	signaller rtclib.Signaller

	// Control channels
	startConnectionCh chan *endpoint
	connectionReadyCh chan webrtcConnectionReadyEvent
	closeCh           chan struct{}
	runLoopStoppedCh  chan struct{}

	// WebRTC API configuration
	api *webrtc.API
}

// Ensure webrtcManager implements rtclib.SignalHandler interface.
var _ rtclib.SignalHandler = (*webrtcManager)(nil)

// newWebRTCManager creates a new WebRTC manager using disco-based signaling.
func newWebRTCManager(c *Conn) *webrtcManager {
	mgr := newWebRTCManagerBase(c)

	mgr.signaller = &discoSignaller{conn: c}
	if err := mgr.signaller.Start(mgr); err != nil {
		c.logf("webrtc: failed to start signaller: %v", err)
		return nil
	}

	go mgr.runLoop()

	return mgr
}

// close shuts down the WebRTC manager.
func (m *webrtcManager) close() error {
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
	for _, ps := range m.peerConnectionsByEndpoint {
		if ps.peerConn != nil {
			ps.peerConn.Close()
		}
	}
	m.peerConnectionsByEndpoint = nil
	m.peerConnectionsByDisco = nil

	return nil
}

// startConnection initiates a WebRTC connection to an endpoint.
func (m *webrtcManager) startConnection(ep *endpoint) {
	if debugAlwaysDERP() {
		return
	}
	select {
	case m.startConnectionCh <- ep:
	case <-m.closeCh:
	default:
		m.logf("webrtc: startConnection queue full for %v", ep.nodeAddr)
	}
}

// ensureConnecting triggers a WebRTC connection to ep if one is not already
// in progress or established. It also retries connections in terminal states
// (Failed, Closed). It is safe to call from the hot send path.
func (m *webrtcManager) ensureConnecting(ep *endpoint) {
	m.mu.RLock()
	ps, exists := m.peerConnectionsByEndpoint[ep]
	m.mu.RUnlock()
	if !exists || ps.state == webrtcStateFailed || ps.state == webrtcStateClosed {
		m.startConnection(ep)
	}
}

// deliverWebRTCMsg delivers one DataChannel message to the receive pipeline.
// It handles both single packets and batches (webrtcBatchMagic framing) so
// the logic is shared between the native detached-reader path and the
// JS/fallback OnMessage callback path.
func (m *webrtcManager) deliverWebRTCMsg(ps *webrtcPeerState, data []byte) {
	if len(data) == 0 {
		return
	}
	// Batch: [0xBA magic][2-byte BE len][pkt]...[2-byte BE len][pkt]
	if data[0] == webrtcBatchMagic {
		data = data[1:]
		for len(data) >= 2 {
			pktLen := int(binary.BigEndian.Uint16(data))
			data = data[2:]
			if pktLen > len(data) {
				m.logf("webrtc: batch framing error for peer %v: pktLen %d > remaining %d",
					ps.remoteDisco.ShortString(), pktLen, len(data))
				return
			}
			m.conn.receiveWebRTC(data[:pktLen], ps.remoteNodeKey)
			data = data[pktLen:]
		}
		return
	}
	m.conn.receiveWebRTC(data, ps.remoteNodeKey)
}

// runDataChannelReader is the per-peer receive loop used when DetachDataChannels
// is enabled (native builds). It reads directly from the detached io.ReadWriteCloser
// into a reused buffer, avoiding the per-message goroutine wakeup and allocation
// that the OnMessage callback path incurs.
func (m *webrtcManager) runDataChannelReader(ps *webrtcPeerState, rwc io.ReadWriteCloser) {
	// Size the buffer to hold the largest possible batch.
	// 64 WireGuard packets × ~1420 bytes + framing < 100 KiB; 256 KiB is safe.
	buf := make([]byte, 256*1024)
	for {
		n, err := rwc.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
				m.logf("webrtc: data channel read error for peer %v: %v", ps.remoteDisco.ShortString(), err)
			}
			ps.dcRW.Store(nil)
			return
		}
		if n > 0 {
			m.deliverWebRTCMsg(ps, buf[:n])
		}
	}
}

// getRemoteAddr returns the actual remote address for a WebRTC peer connection.
func (m *webrtcManager) getRemoteAddr(disco key.DiscoPublic) netip.AddrPort {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if ps, ok := m.peerConnectionsByDisco[disco]; ok && ps.state == webrtcStateConnected {
		return ps.remoteAddr
	}
	return netip.AddrPort{}
}

// markRemoteDescSet marks ps as having a remote description set and flushes
// any ICE candidates that arrived before SetRemoteDescription was called.
// Must be called after SetRemoteDescription succeeds, without holding m.mu.
func (m *webrtcManager) markRemoteDescSet(ps *webrtcPeerState) {
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

// runLoop is the main event loop for the WebRTC manager.
func (m *webrtcManager) runLoop() {
	defer close(m.runLoopStoppedCh)

	retryTicker := time.NewTicker(15 * time.Second)
	defer retryTicker.Stop()

	for {
		select {
		case ep := <-m.startConnectionCh:
			m.handleStartConnection(ep)

		case event := <-m.connectionReadyCh:
			m.handleConnectionReady(event)

		case <-retryTicker.C:
			m.retryFailedConnections()

		case <-m.closeCh:
			return
		}
	}
}

// retryFailedConnections re-queues any connections in a terminal state so they
// get a fresh attempt. This covers cases where both peers restart simultaneously
// and the initial attempt fails before DERP is established.
func (m *webrtcManager) retryFailedConnections() {
	m.mu.RLock()
	var toRetry []*endpoint
	for ep, ps := range m.peerConnectionsByEndpoint {
		if ps.state == webrtcStateFailed || ps.state == webrtcStateClosed {
			toRetry = append(toRetry, ep)
		}
	}
	m.mu.RUnlock()

	for _, ep := range toRetry {
		m.logf("webrtc: retrying failed connection to peer %v", ep.nodeAddr)
		m.startConnection(ep)
	}
}

// handleStartConnection creates a new WebRTC connection to an endpoint.
func (m *webrtcManager) handleStartConnection(ep *endpoint) {
	m.mu.Lock()

	// Check if we already have a connection
	if ps, exists := m.peerConnectionsByEndpoint[ep]; exists {
		switch ps.state {
		case webrtcStateConnecting, webrtcStateConnected:
			m.mu.Unlock()
			return
		default:
			// Terminal state (Failed, Closed): close the old connection and
			// remove it from the maps so we can create a fresh one below.
			ps.peerConn.Close()
			delete(m.peerConnectionsByEndpoint, ep)
			delete(m.peerConnectionsByDisco, ps.remoteDisco)
		}
	}

	// Get disco keys
	localDisco := m.conn.DiscoPublicKey()
	disco := ep.disco.Load()
	if disco == nil {
		m.mu.Unlock()
		m.logf("webrtc: cannot start connection, peer has no disco key")
		return
	}
	remoteDisco := disco.key

	// Check that the peer's DERP address is known before proceeding.
	// If it isn't, the signaling offer will fail immediately. This can
	// happen on startup or after a disco-key rotation before the DERP
	// connection to the new key is established. The next netmap update
	// will re-trigger startConnection once the peer is reachable.
	ep.mu.Lock()
	derpReady := ep.derpAddr.IsValid()
	ep.mu.Unlock()
	if !derpReady {
		m.mu.Unlock()
		return
	}

	m.logf("webrtc: starting connection to peer %v (disco %v)", ep.nodeAddr, remoteDisco.ShortString())

	m.mu.Unlock()

	// Create peer connection
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
		ICETransportPolicy: webrtc.ICETransportPolicyAll,
	}

	peerConn, err := m.api.NewPeerConnection(config)
	if err != nil {
		m.logf("webrtc: failed to create peer connection: %v", err)
		return
	}

	ps := &webrtcPeerState{
		ep:            ep,
		peerConn:      peerConn,
		localDisco:    localDisco,
		remoteDisco:   remoteDisco,
		remoteNodeKey: ep.publicKey,
		state:         webrtcStateConnecting,
		createdAt:     time.Now(),
	}

	// Store peer state
	m.mu.Lock()
	m.peerConnectionsByEndpoint[ep] = ps
	m.peerConnectionsByDisco[remoteDisco] = ps
	m.mu.Unlock()

	// Set up connection state handler
	peerConn.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		m.handleConnectionStateChange(ps, state)
	})

	// Set up ICE candidate handler
	peerConn.OnICECandidate(func(candidate *webrtc.ICECandidate) {
		if candidate != nil {
			m.handleLocalICECandidate(ps, candidate)
		}
	})

	// Create an unordered, unreliable data channel (MaxRetransmits=0).
	// WireGuard is designed to run over raw UDP, which is unordered and
	// unreliable. Using an ordered/reliable DataChannel (the default) wraps
	// WireGuard in SCTP's reliable-ordered-stream semantics, causing
	// head-of-line blocking whenever a packet is lost: SCTP holds back all
	// subsequent packets until the missing one is retransmitted and delivered
	// in order. That is why throughput over WebRTC was worse than DERP.
	// Setting Ordered=false and MaxRetransmits=0 makes the DataChannel behave
	// like a UDP socket, which is exactly what WireGuard expects.
	unordered := false
	maxRetransmits := uint16(0)
	dataChannel, err := peerConn.CreateDataChannel("tailscale-wg", &webrtc.DataChannelInit{
		Ordered:        &unordered,
		MaxRetransmits: &maxRetransmits,
	})
	if err != nil {
		m.logf("webrtc: failed to create data channel: %v", err)
		peerConn.Close()
		return
	}

	ps.dataChannel = dataChannel

	// Set up data channel handlers.
	// With DetachDataChannels enabled, OnMessage cannot be used. Instead we
	// call Detach() inside OnOpen to get a raw io.ReadWriteCloser and spin
	// up a dedicated reader goroutine, which eliminates per-packet callback
	// overhead and goroutine wakeups.
	setOnError(dataChannel, func(err error) {
		m.logf("webrtc: data channel error for peer %v: %v", remoteDisco.ShortString(), err)
	})

	dataChannel.OnOpen(func() {
		// Native: DetachDataChannels was enabled; get a raw io.ReadWriteCloser
		// and spin a dedicated reader goroutine (zero per-message allocations).
		// JS/fallback: Detach() returns an error; fall back to OnMessage
		// callbacks, which is the only API available in the browser.
		if rwc, err := dataChannel.Detach(); err == nil {
			ps.dcRW.Store(&dataChannelRW{rwc})
			go m.runDataChannelReader(ps, rwc)
		} else {
			dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
				m.deliverWebRTCMsg(ps, msg.Data)
			})
		}
		m.logf("webrtc: data channel opened for peer %v", remoteDisco.ShortString())
		m.connectionReadyCh <- webrtcConnectionReadyEvent{
			remoteDisco: remoteDisco,
			ep:          ep,
		}
	})

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
	if err := m.signaller.Offer(localDisco.String(), remoteDisco.String(), &offer); err != nil {
		m.logf("webrtc: failed to send offer: %v", err)
		peerConn.Close()
		m.mu.Lock()
		delete(m.peerConnectionsByEndpoint, ep)
		delete(m.peerConnectionsByDisco, remoteDisco)
		m.mu.Unlock()
		return
	}

	m.logf("webrtc: sent offer to peer %v", remoteDisco.ShortString())
}

// HandleOffer implements rtclib.SignalHandler.
func (m *webrtcManager) HandleOffer(from, to string, offer *webrtc.SessionDescription) {
	m.logf("webrtc: received offer from=%s", from)

	var remoteDisco key.DiscoPublic
	if err := remoteDisco.UnmarshalText([]byte(from)); err != nil {
		m.logf("webrtc: invalid sender disco key: %v", err)
		return
	}

	m.handleRemoteOffer(remoteDisco, offer)
}

// HandleAnswer implements rtclib.SignalHandler.
func (m *webrtcManager) HandleAnswer(from, to string, answer *webrtc.SessionDescription) {
	m.logf("webrtc: received answer from=%s", from)

	var remoteDisco key.DiscoPublic
	if err := remoteDisco.UnmarshalText([]byte(from)); err != nil {
		m.logf("webrtc: invalid sender disco key: %v", err)
		return
	}

	m.handleRemoteAnswer(remoteDisco, answer)
}

// HandleCandidate implements rtclib.SignalHandler.
func (m *webrtcManager) HandleCandidate(from, to string, candidate *webrtc.ICECandidateInit) {
	m.logf("webrtc: received candidate from=%s", from)

	var remoteDisco key.DiscoPublic
	if err := remoteDisco.UnmarshalText([]byte(from)); err != nil {
		m.logf("webrtc: invalid sender disco key: %v", err)
		return
	}

	m.handleRemoteCandidate(remoteDisco, candidate)
}

// handleRemoteOffer processes an incoming offer from a peer.
func (m *webrtcManager) handleRemoteOffer(remoteDisco key.DiscoPublic, offer *webrtc.SessionDescription) {

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
			localDisco := m.conn.DiscoPublicKey()
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
				delete(m.peerConnectionsByEndpoint, ps.ep)
				delete(m.peerConnectionsByDisco, remoteDisco)
				m.mu.Unlock()
				exists = false
			}
		case webrtc.SignalingStateStable:
			if ps.state == webrtcStateConnected || ps.state == webrtcStateConnecting {
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
			delete(m.peerConnectionsByEndpoint, ps.ep)
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
		// We received an offer but don't have a connection yet.
		// Find the endpoint by disco key and create peer connection state.
		ep := m.conn.findEndpointByDisco(remoteDisco)
		if ep == nil {
			m.logf("webrtc: received offer from unknown peer %v with no endpoint", remoteDisco.ShortString())
			return
		}

		m.logf("webrtc: received offer from peer %v, creating answerer connection", remoteDisco.ShortString())

		// Create peer connection for incoming offer
		config := webrtc.Configuration{
			ICEServers: []webrtc.ICEServer{
				{
					URLs: []string{"stun:stun.l.google.com:19302"},
				},
			},
			ICETransportPolicy: webrtc.ICETransportPolicyAll,
		}

		peerConn, err := m.api.NewPeerConnection(config)
		if err != nil {
			m.logf("webrtc: failed to create peer connection for incoming offer: %v", err)
			return
		}

		localDisco := m.conn.DiscoPublicKey()
		ps = &webrtcPeerState{
			ep:            ep,
			peerConn:      peerConn,
			localDisco:    localDisco,
			remoteDisco:   remoteDisco,
			remoteNodeKey: ep.publicKey,
			state:         webrtcStateConnecting,
			createdAt:     time.Now(),
		}

		// Store peer state
		m.mu.Lock()
		m.peerConnectionsByEndpoint[ep] = ps
		m.peerConnectionsByDisco[remoteDisco] = ps
		m.mu.Unlock()

		// Set up connection state handler
		peerConn.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
			m.handleConnectionStateChange(ps, state)
		})

		// Set up ICE candidate handler
		peerConn.OnICECandidate(func(candidate *webrtc.ICECandidate) {
			if candidate != nil {
				m.handleLocalICECandidate(ps, candidate)
			}
		})

		// Set up data channel handler (for answerer, we wait for the data channel from offerer).
		peerConn.OnDataChannel(func(dc *webrtc.DataChannel) {
			m.logf("webrtc: received data channel from peer %v", remoteDisco.ShortString())
			ps.dataChannel = dc

			setOnError(dc, func(err error) {
				m.logf("webrtc: data channel error for peer %v: %v", remoteDisco.ShortString(), err)
			})

			dc.OnOpen(func() {
				if rwc, err := dc.Detach(); err == nil {
					ps.dcRW.Store(&dataChannelRW{rwc})
					go m.runDataChannelReader(ps, rwc)
				} else {
					dc.OnMessage(func(msg webrtc.DataChannelMessage) {
						m.deliverWebRTCMsg(ps, msg.Data)
					})
				}
				m.logf("webrtc: data channel opened for peer %v", remoteDisco.ShortString())
				m.connectionReadyCh <- webrtcConnectionReadyEvent{
					remoteDisco: remoteDisco,
					ep:          ep,
				}
			})
		})
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

// handleRemoteAnswer processes an incoming answer from a peer.
func (m *webrtcManager) handleRemoteAnswer(remoteDisco key.DiscoPublic, answer *webrtc.SessionDescription) {
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
func (m *webrtcManager) handleRemoteCandidate(remoteDisco key.DiscoPublic, candidate *webrtc.ICECandidateInit) {
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

// handleLocalICECandidate sends a local ICE candidate to a peer via signaling.
func (m *webrtcManager) handleLocalICECandidate(ps *webrtcPeerState, candidate *webrtc.ICECandidate) {
	candidateInit := candidate.ToJSON()
	if err := m.signaller.Candidate(ps.localDisco.String(), ps.remoteDisco.String(), &candidateInit); err != nil {
		m.logf("webrtc: failed to send candidate: %v", err)
		return
	}

	m.logf("webrtc: sent ICE candidate to peer %v", ps.remoteDisco.ShortString())
}

// handleConnectionStateChange handles WebRTC connection state changes.
func (m *webrtcManager) handleConnectionStateChange(ps *webrtcPeerState, state webrtc.PeerConnectionState) {
	m.logf("webrtc: connection state changed to %s for peer %v", state.String(), ps.remoteDisco.ShortString())

	m.mu.Lock()

	var clearBestAddr bool
	switch state {
	case webrtc.PeerConnectionStateConnected:
		ps.state = webrtcStateConnected
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
		ps.state = webrtcStateFailed
		ps.lastError = errors.New("connection failed")
		ps.dcRW.Store(nil)
		clearBestAddr = true
	case webrtc.PeerConnectionStateClosed:
		ps.state = webrtcStateClosed
		ps.dcRW.Store(nil)
		clearBestAddr = true
	case webrtc.PeerConnectionStateDisconnected:
		// Transient state — do not clear bestAddr yet; the connection may recover.
	}

	m.mu.Unlock()

	// clearWebRTCBestAddr acquires ep.mu; must be called without m.mu held.
	if clearBestAddr {
		m.clearWebRTCBestAddr(ps)
	}
}

// clearWebRTCBestAddr resets the endpoint's bestAddr if it is currently the
// WebRTC magic address, so that traffic immediately falls back to DERP.
// Must be called without holding m.mu or ep.mu.
func (m *webrtcManager) clearWebRTCBestAddr(ps *webrtcPeerState) {
	ps.ep.mu.Lock()
	defer ps.ep.mu.Unlock()
	if ps.ep.bestAddr.ap.Addr() == tailcfg.WebRTCMagicIPAddr {
		ps.ep.bestAddr = addrQuality{}
		ps.ep.trustBestAddrUntil = 0
		m.logf("webrtc: cleared WebRTC bestAddr for peer %v, falling back to DERP", ps.remoteDisco.ShortString())
	}
}

// handleConnectionReady marks a WebRTC connection as ready and updates endpoint.
func (m *webrtcManager) handleConnectionReady(event webrtcConnectionReadyEvent) {
	m.logf("webrtc: connection ready for peer %v", event.remoteDisco.ShortString())
	if debugAlwaysDERP() {
		return
	}

	// Update endpoint to use WebRTC path
	event.ep.mu.Lock()
	defer event.ep.mu.Unlock()

	// Use a fixed port number for WebRTC connections (similar to DERP)
	// The magic IP identifies this as WebRTC, not UDP
	webrtcAddr := addrQuality{
		epAddr: epAddr{
			ap: netip.AddrPortFrom(tailcfg.WebRTCMagicIPAddr, 12345),
		},
		latency: 0, // Will be determined by disco pings, same as DERP
	}

	// Set as bestAddr if better than current
	now := mono.Now()
	if betterAddr(webrtcAddr, event.ep.bestAddr) {
		event.ep.bestAddr = webrtcAddr
		event.ep.bestAddrAt = now
		event.ep.trustBestAddrUntil = now.Add(5 * time.Minute)
		m.logf("webrtc: updated endpoint %v with WebRTC path", event.ep.nodeAddr)
	}
}

// sendPacket sends a packet over a WebRTC data channel.
// The hot path is lock-free: we take a read-lock (not write-lock) to look up
// the peer state, then do an atomic load for the detached channel. Multiple
// concurrent senders for different peers never contend.
func (m *webrtcManager) sendPacket(disco key.DiscoPublic, b []byte) error {
	m.mu.RLock()
	ps, ok := m.peerConnectionsByDisco[disco]
	m.mu.RUnlock()
	if !ok {
		return errors.New("no WebRTC connection")
	}

	// Native path: DetachDataChannels was enabled; use the raw io.ReadWriteCloser.
	if rw := ps.dcRW.Load(); rw != nil {
		if _, err := rw.Write(b); err != nil {
			return fmt.Errorf("send failed: %w", err)
		}
		return nil
	}

	// JS/fallback path: use DataChannel.Send() directly.
	dc := ps.dataChannel
	if dc == nil || dc.ReadyState() != webrtc.DataChannelStateOpen {
		return errors.New("data channel not ready")
	}
	return dc.Send(b)
}

// receiveWebRTC reads packets from the WebRTC receive channel.
// It is called by wireguard-go through the conn.Bind interface.
// It blocks until at least one packet is available, then drains as many
// additional packets as are immediately ready (up to len(buffs)).
func (c *connBind) receiveWebRTC(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	// Block until the first packet arrives (or the channel is closed).
	wr, ok := <-c.webrtcRecvCh
	if !ok || c.isClosed() {
		return 0, net.ErrClosed
	}
	num := 0
	n, ep := c.processWebRTCReadResult(wr, buffs[num])
	if n > 0 {
		sizes[num] = n
		eps[num] = ep
		num++
	}
	// Drain any additional packets that are immediately available.
	for num < len(buffs) {
		select {
		case wr, ok = <-c.webrtcRecvCh:
			if !ok || c.isClosed() {
				if num > 0 {
					return num, nil
				}
				return 0, net.ErrClosed
			}
			n, ep = c.processWebRTCReadResult(wr, buffs[num])
			if n > 0 {
				sizes[num] = n
				eps[num] = ep
				num++
			}
		default:
			return num, nil
		}
	}
	return num, nil
}
