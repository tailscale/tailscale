// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/pion/webrtc/v4"
	"tailscale.com/rtclib"
	"tailscale.com/types/logger"
)

// Ensure signalingClient implements rtclib.Signaller interface.
var _ rtclib.Signaller = (*signalingClient)(nil)

// signalingClient manages WebSocket connection to signaling server.
type signalingClient struct {
	url    string
	logf   logger.Logf
	conn   *websocket.Conn
	connMu sync.Mutex

	// Message handler
	handler rtclib.SignalHandler

	// Control channels
	ctx       context.Context
	ctxCancel context.CancelFunc
	sendCh    chan *rtclib.SignalingMessage
	closedCh  chan struct{}

	// Reconnection state
	reconnectDelay time.Duration
	maxDelay       time.Duration
}

// newSignalingClient creates a new signaling client.
func newSignalingClient(url string, logf logger.Logf) *signalingClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &signalingClient{
		url:            url,
		logf:           logf,
		ctx:            ctx,
		ctxCancel:      cancel,
		sendCh:         make(chan *rtclib.SignalingMessage, 16),
		closedCh:       make(chan struct{}),
		reconnectDelay: time.Second,
		maxDelay:       30 * time.Second,
	}
}

// Start begins the signaling client's connection and message loops.
func (sc *signalingClient) Start(handler rtclib.SignalHandler) error {
	sc.handler = handler
	if err := sc.connect(); err != nil {
		return fmt.Errorf("initial signaling connection failed: %w", err)
	}
	go sc.runLoop()
	return nil
}

// connect establishes WebSocket connection to signaling server.
func (sc *signalingClient) connect() error {
	sc.connMu.Lock()
	defer sc.connMu.Unlock()

	if sc.conn != nil {
		return nil // already connected
	}

	conn, _, err := websocket.Dial(sc.ctx, sc.url, nil)
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}

	sc.conn = conn
	sc.reconnectDelay = time.Second // reset backoff on successful connection
	sc.logf("signaling: connected to %s", sc.url)
	return nil
}

// Close closes the signaling client.
func (sc *signalingClient) Close() error {
	// Cancel context to signal all goroutines to stop
	sc.ctxCancel()

	// Close the connection to unblock any read/write operations
	sc.connMu.Lock()
	if sc.conn != nil {
		sc.conn.Close(websocket.StatusNormalClosure, "")
	}
	sc.connMu.Unlock()

	// Wait for runLoop to finish with timeout
	select {
	case <-sc.closedCh:
	case <-time.After(2 * time.Second):
		sc.logf("signaling: close timed out, forcing shutdown")
	}

	sc.connMu.Lock()
	defer sc.connMu.Unlock()
	sc.conn = nil
	return nil
}

// send queues a message to be sent to the signaling server.
func (sc *signalingClient) send(msg *rtclib.SignalingMessage) error {
	select {
	case sc.sendCh <- msg:
		return nil
	case <-sc.ctx.Done():
		return sc.ctx.Err()
	default:
		return errors.New("signaling send queue full")
	}
}

// runLoop manages connection lifecycle and message routing.
func (sc *signalingClient) runLoop() {
	defer close(sc.closedCh)

	for {
		select {
		case <-sc.ctx.Done():
			return
		default:
		}

		// Ensure we're connected
		if err := sc.ensureConnected(); err != nil {
			sc.logf("signaling: connection failed, retrying in %v: %v", sc.reconnectDelay, err)
			select {
			case <-time.After(sc.reconnectDelay):
				sc.reconnectDelay = min(sc.reconnectDelay*2, sc.maxDelay)
				continue
			case <-sc.ctx.Done():
				return
			}
		}

		// Run read/write loops
		errCh := make(chan error, 2)
		go sc.readLoop(errCh)
		go sc.writeLoop(errCh)

		// Wait for error or context cancellation
		select {
		case err := <-errCh:
			sc.logf("signaling: connection error: %v", err)
			sc.disconnect()
		case <-sc.ctx.Done():
			sc.disconnect()
			return
		}
	}
}

// ensureConnected ensures connection is established.
func (sc *signalingClient) ensureConnected() error {
	sc.connMu.Lock()
	connected := sc.conn != nil
	sc.connMu.Unlock()

	if connected {
		return nil
	}

	return sc.connect()
}

// disconnect closes the current connection.
func (sc *signalingClient) disconnect() {
	sc.connMu.Lock()
	defer sc.connMu.Unlock()

	if sc.conn != nil {
		sc.conn.Close(websocket.StatusNormalClosure, "")
		sc.conn = nil
		sc.logf("signaling: disconnected")
	}
}

// readLoop reads messages from WebSocket.
func (sc *signalingClient) readLoop(errCh chan<- error) {
	for {
		sc.connMu.Lock()
		conn := sc.conn
		sc.connMu.Unlock()

		if conn == nil {
			errCh <- errors.New("no connection")
			return
		}

		var msg rtclib.SignalingMessage
		if err := wsjson.Read(sc.ctx, conn, &msg); err != nil {
			errCh <- fmt.Errorf("read failed: %w", err)
			return
		}

		if sc.handler != nil {
			switch msg.Type {
			case rtclib.MessageTypeOffer:
				sc.handler.HandleOffer(msg.From, msg.To, msg.Offer)
			case rtclib.MessageTypeAnswer:
				sc.handler.HandleAnswer(msg.From, msg.To, msg.Answer)
			case rtclib.MessageTypeCandidate:
				sc.handler.HandleCandidate(msg.From, msg.To, msg.Candidate)
			default:
				sc.logf("signaling: unknown message type: %s", msg.Type)
			}
		}
	}
}

// writeLoop writes messages to WebSocket.
func (sc *signalingClient) writeLoop(errCh chan<- error) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case msg := <-sc.sendCh:
			sc.connMu.Lock()
			conn := sc.conn
			sc.connMu.Unlock()

			if conn == nil {
				errCh <- errors.New("no connection")
				return
			}

			if err := wsjson.Write(sc.ctx, conn, msg); err != nil {
				errCh <- fmt.Errorf("write failed: %w", err)
				return
			}

		case <-ticker.C:
			// Send ping to keep connection alive
			sc.connMu.Lock()
			conn := sc.conn
			sc.connMu.Unlock()

			if conn == nil {
				errCh <- errors.New("no connection")
				return
			}

			if err := conn.Ping(sc.ctx); err != nil {
				errCh <- fmt.Errorf("ping failed: %w", err)
				return
			}

		case <-sc.ctx.Done():
			return
		}
	}
}

// Offer sends an SDP offer to a peer.
func (sc *signalingClient) Offer(from, to string, offer *webrtc.SessionDescription) error {
	return sc.send(&rtclib.SignalingMessage{
		Type:  rtclib.MessageTypeOffer,
		From:  from,
		To:    to,
		Offer: offer,
	})
}

// Answer sends an SDP answer to a peer.
func (sc *signalingClient) Answer(from, to string, answer *webrtc.SessionDescription) error {
	return sc.send(&rtclib.SignalingMessage{
		Type:   rtclib.MessageTypeAnswer,
		From:   from,
		To:     to,
		Answer: answer,
	})
}

// Candidate sends an ICE candidate to a peer.
func (sc *signalingClient) Candidate(from, to string, candidate *webrtc.ICECandidateInit) error {
	return sc.send(&rtclib.SignalingMessage{
		Type:      rtclib.MessageTypeCandidate,
		From:      from,
		To:        to,
		Candidate: candidate,
	})
}
