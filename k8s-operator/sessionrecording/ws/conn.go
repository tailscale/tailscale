// Copyright (c) Tailscale Inc & contributors
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

	if _, err := c.readBuf.Write(b[:n]); err != nil {
		return 0, fmt.Errorf("[unexpected] error writing message contents to read buffer: %w", err)
	}

	if _, err := c.processFrames(&c.readBuf, &c.currentReadMsg); err != nil {
		return 0, err
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

	if _, err := c.writeBuf.Write(b); err != nil {
		c.log.Errorf("write: error writing to write buf: %v", err)
		return 0, fmt.Errorf("[unexpected] error writing to internal write buffer: %w", err)
	}

	raw, err := c.processFrames(&c.writeBuf, &c.currentWriteMsg)
	if err != nil {
		return 0, err
	}
	if len(raw) > 0 {
		if _, err := c.Conn.Write(raw); err != nil {
			return 0, err
		}
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

// handleData records a finalized data message to the session recorder.
// It handles resize messages (updating terminal dimensions and writing the
// CastHeader on the first one) and stdout/stderr messages (recording output).
// Other stream IDs (stdin, error) are ignored.
func (c *conn) handleData(msg *message) error {
	switch msg.streamID.Load() {
	case remotecommand.StreamResize:
		if !c.hasTerm {
			return nil
		}
		var rm tsrecorder.ResizeMsg
		if err := json.Unmarshal(msg.payload, &rm); err != nil {
			return fmt.Errorf("error unmarshalling resize message: %w", err)
		}
		c.ch.Width = rm.Width
		c.ch.Height = rm.Height

		// The first resize writes the CastHeader and unblocks output recording.
		var headerErr error
		var isInitialResize bool
		c.writeCastHeaderOnce.Do(func() {
			isInitialResize = true
			headerErr = c.rec.WriteCastHeader(c.ch)
			close(c.initialCastHeaderSent)
		})
		if headerErr != nil {
			return fmt.Errorf("error writing CastHeader: %w", headerErr)
		}
		if !isInitialResize {
			if err := c.rec.WriteResize(rm.Height, rm.Width); err != nil {
				return fmt.Errorf("error writing resize message: %w", err)
			}
		}
	case remotecommand.StreamStdOut, remotecommand.StreamStdErr:
		// Wait for the CastHeader before recording any output.
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-c.initialCastHeaderSent:
			if err := c.rec.WriteOutput(msg.payload); err != nil {
				return fmt.Errorf("error writing message to recorder: %w", err)
			}
		}
	}
	return nil
}

// processFrames drains complete WebSocket frames from buf, recording session
// data via handleData for finalized binary messages. It returns the raw bytes
// of every consumed frame so the Write path can forward them to the underlying
// connection. Incomplete frames are left in buf for the next call.
//
// Control frames are consumed whole without inspection. Non-binary data frames
// are unexpected (k8s only uses binary) and cause the buffer to be discarded.
func (c *conn) processFrames(
	buf *bytes.Buffer,
	curMsg **message,
) ([]byte, error) {
	var raw []byte
	for buf.Len() != 0 {
		b := buf.Bytes()
		if len(b) < 2 {
			return raw, nil
		}

		// Continuation frames (opcode 0) inherit the type of the in-progress message.
		typ := messageType(opcode(b))
		if typ == noOpcode && *curMsg != nil {
			typ = (*curMsg).typ
		}

		// Control frames: pass through without inspection.
		if isControlMessage(typ) {
			maskSet := isMasked(b)
			payloadLen, payloadOffset, _, err := fragmentDimensions(b, maskSet)
			if err != nil {
				return nil, fmt.Errorf("error parsing control frame: %w", err)
			}
			frameLen := int(payloadOffset + payloadLen)
			if len(b) < frameLen {
				return raw, nil // incomplete control frame
			}
			raw = append(raw, b[:frameLen]...)
			buf.Next(frameLen)
			continue
		}

		// k8s remotecommand only uses binary data messages.
		if typ != binaryMessage {
			c.log.Infof("[unexpected] received a data message with a type that is not binary message type %v", typ)
			buf.Reset()
			return raw, nil
		}

		// Continue a fragmented message or start a new one.
		msg := &message{typ: typ}
		if *curMsg != nil && !(*curMsg).isFinalized {
			msg = *curMsg
		}

		ok, err := msg.Parse(b, c.log)
		if err != nil {
			return nil, fmt.Errorf("error parsing message: %w", err)
		}
		if !ok {
			*curMsg = msg
			return raw, nil // incomplete fragment, wait for more bytes
		}
		buf.Next(len(msg.raw))
		*curMsg = msg

		raw = append(raw, msg.raw...)
		if msg.isFinalized && len(msg.payload) > 0 {
			if err := c.handleData(msg); err != nil {
				return nil, err
			}
		}
	}
	return raw, nil
}

// opcode reads the websocket message opcode that denotes the message type.
// opcode is contained in bits [4-8] of the message.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
func opcode(b []byte) int {
	// 0xf = 00001111; b & 00001111 zeroes out bits [0 - 3] of b
	var mask byte = 0xf
	return int(b[0] & mask)
}
