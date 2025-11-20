// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// package ws has functionality to parse 'kubectl exec/attach' sessions streamed using
// WebSocket protocol.
package ws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/remotecommand"
	"tailscale.com/k8s-operator/sessionrecording/tsrecorder"
	"tailscale.com/sessionrecording"
)

// New wraps the provided network connection and returns a connection whose reads and writes will get triggered as data is received on the hijacked connection.
// The connection must be a hijacked connection for a 'kubectl exec/attach' session using WebSocket protocol and a *.channel.k8s.io subprotocol.
// The hijacked connection is used to transmit *.channel.k8s.io streams between Kubernetes client ('kubectl') and the destination proxy controlled by Kubernetes.
// Data read from the underlying network connection is data sent via one of the streams from the client to the container.
// Data written to the underlying connection is data sent from the container to the client.
// We parse the data and send everything for the stdout/stderr streams to the configured tsrecorder as an asciinema recording with the provided header.
// https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/4006-transition-spdy-to-websockets#proposal-new-remotecommand-sub-protocol-version---v5channelk8sio
func New(ctx context.Context, c net.Conn, rec *tsrecorder.Client, ch sessionrecording.CastHeader, hasTerm bool, log *zap.SugaredLogger) (net.Conn, error) {
	lc := &conn{
		Conn:                  c,
		ctx:                   ctx,
		rec:                   rec,
		ch:                    ch,
		hasTerm:               hasTerm,
		log:                   log,
		initialCastHeaderSent: make(chan struct{}, 1),
	}

	// if there is no term, we don't need to wait for a resize message
	if !hasTerm {
		var err error
		lc.writeCastHeaderOnce.Do(func() {
			// If this is a session with a terminal attached,
			// we must wait for the terminal width and
			// height to be parsed from a resize message
			// before sending CastHeader, else tsrecorder
			// will not be able to play this recording.
			err = lc.rec.WriteCastHeader(ch)
			close(lc.initialCastHeaderSent)
		})
		if err != nil {
			return nil, fmt.Errorf("error writing CastHeader: %w", err)
		}
	}

	return lc, nil
}

// conn is a wrapper around net.Conn. It reads the bytestream
// for a 'kubectl exec/attach' session, sends session recording data to the configured
// recorder and forwards the raw bytes to the original destination.
// A new conn is created per session.
// conn only knows to how to read a 'kubectl exec/attach' session that is streamed using WebSocket protocol.
// https://www.rfc-editor.org/rfc/rfc6455
type conn struct {
	net.Conn

	ctx context.Context
	// rec knows how to send data to a tsrecorder instance.
	rec *tsrecorder.Client

	// The following fields are related to sending asciinema CastHeader.
	// CastHeader must be sent before any payload. If the session has a
	// terminal attached, the CastHeader must have '.Width' and '.Height'
	// fields set for the tsrecorder UI to be able to play the recording.
	// For 'kubectl exec/attach' sessions, terminal width and height are sent as a
	// resize message on resize stream from the client when the session
	// starts as well as at any time the client detects a terminal change.
	// We can intercept the resize message on Read calls. As there is no
	// guarantee that the resize message from client will be intercepted
	// before server writes stdout messages that we must record, we need to
	// ensure that parsing stdout/stderr messages written to the connection
	// waits till a resize message has been received and a CastHeader with
	// correct terminal dimensions can be written.

	// ch is asciinema CastHeader for the current session.
	// https://docs.asciinema.org/manual/asciicast/v2/#header
	ch sessionrecording.CastHeader
	// writeCastHeaderOnce is used to ensure CastHeader gets sent to tsrecorder once.
	writeCastHeaderOnce sync.Once
	hasTerm             bool // whether the session has TTY attached
	// initialCastHeaderSent is a boolean that is set to ensure that the cast
	// header is the first thing that is streamed to the session recorder.
	// Otherwise the stream will fail.
	initialCastHeaderSent chan struct{}

	log *zap.SugaredLogger

	rmu sync.Mutex // sequences reads
	// currentReadMsg contains parsed contents of a websocket binary data message that
	// is currently being read from the underlying net.Conn.
	currentReadMsg *message
	// readBuf contains bytes for a currently parsed binary data message
	// read from the underlying conn. If the message is masked, it is
	// unmasked in place, so having this buffer allows us to avoid modifying
	// the original byte array.
	readBuf bytes.Buffer

	wmu    sync.Mutex // sequences writes
	closed bool       // connection is closed
	// writeBuf contains bytes for a currently parsed binary data message
	// being written to the underlying conn. If the message is masked, it is
	// unmasked in place, so having this buffer allows us to avoid modifying
	// the original byte array.
	writeBuf bytes.Buffer
	// currentWriteMsg contains parsed contents of a websocket binary data message that
	// is currently being written to the underlying net.Conn.
	currentWriteMsg *message
}

// Read reads bytes from the original connection and parses them as websocket
// message fragments.
// Bytes read from the original connection are the bytes sent from the Kubernetes client (kubectl) to the destination container via kubelet.

// If the message is for the resize stream, sets the width
// and height of the CastHeader for this connection.
// The fragment can be incomplete.
func (c *conn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	n, err := c.Conn.Read(b)
	if err != nil {
		// It seems that we sometimes get a wrapped io.EOF, but the
		// caller checks for io.EOF with ==.
		if errors.Is(err, io.EOF) {
			err = io.EOF
		}
		return 0, err
	}
	if n == 0 {
		c.log.Debug("[unexpected] Read called for 0 length bytes")
		return 0, nil
	}

	// TODO(tomhjp): If we get multiple frames in a single Read with different
	// types, we may parse the second frame with the wrong type.
	typ := messageType(opcode(b))
	if (typ == noOpcode && c.readMsgIsIncomplete()) || c.readBufHasIncompleteFragment() { // subsequent fragment
		if typ, err = c.curReadMsgType(); err != nil {
			return 0, err
		}
	}

	// A control message can not be fragmented and we are not interested in
	// these messages. Just return.
	// TODO(tomhjp): If we get multiple frames in a single Read, we may skip
	// some non-control messages.
	if isControlMessage(typ) {
		return n, nil
	}

	// The only data message type that Kubernetes supports is binary message.
	// If we received another message type, return and let the API server close the connection.
	// https://github.com/kubernetes/client-go/blob/release-1.30/tools/remotecommand/websocket.go#L281
	if typ != binaryMessage {
		c.log.Infof("[unexpected] received a data message with a type that is not binary message type %v", typ)
		return n, nil
	}

	if _, err := c.readBuf.Write(b[:n]); err != nil {
		return 0, fmt.Errorf("[unexpected] error writing message contents to read buffer: %w", err)
	}

	for c.readBuf.Len() != 0 {
		readMsg := &message{typ: typ} // start a new message...
		// ... or pick up an already started one if the previous fragment was not final.
		if c.readMsgIsIncomplete() {
			readMsg = c.currentReadMsg
		}

		ok, err := readMsg.Parse(c.readBuf.Bytes(), c.log)
		if err != nil {
			return 0, fmt.Errorf("error parsing message: %v", err)
		}
		if !ok { // incomplete fragment
			return n, nil
		}
		c.readBuf.Next(len(readMsg.raw))

		if readMsg.isFinalized && !c.readMsgIsIncomplete() {
			// we want to send stream resize messages for terminal sessions
			// Stream IDs for websocket streams are static.
			// https://github.com/kubernetes/client-go/blob/v0.30.0-rc.1/tools/remotecommand/websocket.go#L218
			if readMsg.streamID.Load() == remotecommand.StreamResize && c.hasTerm {
				var msg tsrecorder.ResizeMsg
				if err = json.Unmarshal(readMsg.payload, &msg); err != nil {
					return 0, fmt.Errorf("error umarshalling resize message: %w", err)
				}

				c.ch.Width = msg.Width
				c.ch.Height = msg.Height

				var isInitialResize bool
				c.writeCastHeaderOnce.Do(func() {
					isInitialResize = true
					// If this is a session with a terminal attached,
					// we must wait for the terminal width and
					// height to be parsed from a resize message
					// before sending CastHeader, else tsrecorder
					// will not be able to play this recording.
					err = c.rec.WriteCastHeader(c.ch)
					close(c.initialCastHeaderSent)
				})
				if err != nil {
					return 0, fmt.Errorf("error writing CastHeader: %w", err)
				}

				if !isInitialResize {
					if err := c.rec.WriteResize(msg.Height, msg.Width); err != nil {
						return 0, fmt.Errorf("error writing resize message: %w", err)
					}
				}
			}
		}

		c.currentReadMsg = readMsg
	}

	return n, nil
}

// Write parses the written bytes as WebSocket message fragment. If the message
// is for stdout or stderr streams, it is written to the configured tsrecorder.
// A message fragment can be incomplete.
func (c *conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if len(b) == 0 {
		c.log.Debug("[unexpected] Write called with 0 bytes")
		return 0, nil
	}

	typ := messageType(opcode(b))
	// If we are in process of parsing a message fragment, the received
	// bytes are not structured as a message fragment and can not be used to
	// determine a message fragment.
	if c.writeBufHasIncompleteFragment() { // buffer contains previous incomplete fragment
		var err error
		if typ, err = c.curWriteMsgType(); err != nil {
			return 0, err
		}
	}

	if isControlMessage(typ) {
		return c.Conn.Write(b)
	}

	writeMsg := &message{typ: typ} // start a new message...
	// ... or continue the existing one if it has not been finalized.
	if c.writeMsgIsIncomplete() || c.writeBufHasIncompleteFragment() {
		writeMsg = c.currentWriteMsg
	}

	if _, err := c.writeBuf.Write(b); err != nil {
		c.log.Errorf("write: error writing to write buf: %v", err)
		return 0, fmt.Errorf("[unexpected] error writing to internal write buffer: %w", err)
	}

	ok, err := writeMsg.Parse(c.writeBuf.Bytes(), c.log)
	if err != nil {
		c.log.Errorf("write: parsing a message errored: %v", err)
		return 0, fmt.Errorf("write: error parsing message: %v", err)
	}

	c.currentWriteMsg = writeMsg
	if !ok { // incomplete fragment
		return len(b), nil
	}

	c.writeBuf.Next(len(writeMsg.raw)) // advance frame

	if len(writeMsg.payload) != 0 && writeMsg.isFinalized {
		if writeMsg.streamID.Load() == remotecommand.StreamStdOut || writeMsg.streamID.Load() == remotecommand.StreamStdErr {
			// we must wait for confirmation that the initial cast header was sent before proceeding with any more writes
			select {
			case <-c.ctx.Done():
				return 0, c.ctx.Err()
			case <-c.initialCastHeaderSent:
				if err := c.rec.WriteOutput(writeMsg.payload); err != nil {
					return 0, fmt.Errorf("error writing message to recorder: %w", err)
				}
			}
		}
	}

	_, err = c.Conn.Write(c.currentWriteMsg.raw)
	if err != nil {
		c.log.Errorf("write: error writing to conn: %v", err)
	}

	return len(b), nil
}

func (c *conn) Close() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	connCloseErr := c.Conn.Close()
	recCloseErr := c.rec.Close()
	return errors.Join(connCloseErr, recCloseErr)
}

// writeBufHasIncompleteFragment returns true if the latest data message
// fragment written to the connection was incomplete and the following write
// must be the remaining payload bytes of that fragment.
func (c *conn) writeBufHasIncompleteFragment() bool {
	return c.writeBuf.Len() != 0
}

// readBufHasIncompleteFragment returns true if the latest data message
// fragment read from the connection was incomplete and the following read
// must be the remaining payload bytes of that fragment.
func (c *conn) readBufHasIncompleteFragment() bool {
	return c.readBuf.Len() != 0
}

// writeMsgIsIncomplete returns true if the latest WebSocket message written to
// the connection was fragmented and the next data message fragment written to
// the connection must be a fragment of that message.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.4
func (c *conn) writeMsgIsIncomplete() bool {
	return c.currentWriteMsg != nil && !c.currentWriteMsg.isFinalized
}

// readMsgIsIncomplete returns true if the latest WebSocket message written to
// the connection was fragmented and the next data message fragment written to
// the connection must be a fragment of that message.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.4
func (c *conn) readMsgIsIncomplete() bool {
	return c.currentReadMsg != nil && !c.currentReadMsg.isFinalized
}

func (c *conn) curReadMsgType() (messageType, error) {
	if c.currentReadMsg != nil {
		return c.currentReadMsg.typ, nil
	}
	return 0, errors.New("[unexpected] attempted to determine type for nil message")
}

func (c *conn) curWriteMsgType() (messageType, error) {
	if c.currentWriteMsg != nil {
		return c.currentWriteMsg.typ, nil
	}
	return 0, errors.New("[unexpected] attempted to determine type for nil message")
}

// opcode reads the websocket message opcode that denotes the message type.
// opcode is contained in bits [4-8] of the message.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
func opcode(b []byte) int {
	// 0xf = 00001111; b & 00001111 zeroes out bits [0 - 3] of b
	var mask byte = 0xf
	return int(b[0] & mask)
}
