// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// package ws has functionality to parse 'kubectl exec' sessions streamed using
// WebSockets protocol.
package ws

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/util/remotecommand"
	"tailscale.com/k8s-operator/session-recording/tsrecorder"
	"tailscale.com/util/multierr"
)

// New returns a wrapper around net.Conn that intercepts reads and writes for a
// websocket streaming session over the provided net.Conn, parses the data as
// websocket messages and sends message payloads for STDIN/STDOUT streams to a
// tsrecorder instance using the provided client. Caller must ensure that the
// session is streamed using WebSockets protocol.
func New(c net.Conn, rec *tsrecorder.Client, ch tsrecorder.CastHeader, log *zap.SugaredLogger) net.Conn {
	return &conn{
		Conn: c,
		rec:  rec,
		ch:   ch,
		log:  log,
	}
}

// conn is a wrapper around net.Conn. It reads the bytestream
// for a 'kubectl exec' session, sends session recording data to the configured
// recorder and forwards the raw bytes to the original destination.
// A new conn is created per session.
// conn only knows to how to read a 'kubectl exec' session that is streamed using WebSocket protocol.
// https://www.rfc-editor.org/rfc/rfc6455
type conn struct {
	net.Conn
	// rec knows how to send data to a tsrecorder instance.
	rec *tsrecorder.Client
	// ch is the asiinema CastHeader for a session.
	ch  tsrecorder.CastHeader
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

	wmu                 sync.Mutex // sequences writes
	writeCastHeaderOnce sync.Once
	closed              bool
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
// message fragments. If the message is for the resize stream, sets the width
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

	typ := messageType(opcode(b))
	if typ == noOpcode && c.currentReadMsg != nil && !c.currentReadMsg.isFinalized { // subsequent fragment
		typ = c.currentReadMsg.typ
	}

	// A control message can not be fragmented and we are not interested in
	// these messages. Just return.
	if isControlMessage(typ) {
		return n, nil
	}

	// The only data message type that Kubernetes supports is binary message.
	// If we received another message type, return and let the API server close the connection.
	// https://github.com/kubernetes/client-go/blob/release-1.30/tools/remotecommand/websocket.go#L281
	if typ != binaryMessage {
		c.log.Info("[unexpected] received a data message with a type that is not binary message type %d", typ)
		return n, nil
	}
	if _, err := c.readBuf.Write(b[:n]); err != nil {
		return 0, fmt.Errorf("[unexpected] error writing message contents to read buffer: %w", err)
	}

	readMsg := &message{typ: typ} // start a new message...
	// ... or pick up an already started one if the previous fragment was not final.
	if c.currentReadMsg != nil && !c.currentReadMsg.isFinalized {
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

	if readMsg.isFinalized {
		// Stream IDs for websocket streams are static.
		// https://github.com/kubernetes/client-go/blob/v0.30.0-rc.1/tools/remotecommand/websocket.go#L218
		if readMsg.streamID.Load() == remotecommand.StreamResize {
			var err error
			var msg tsrecorder.ResizeMsg
			if err = json.Unmarshal(readMsg.payload, &msg); err != nil {
				return 0, fmt.Errorf("error umarshalling resize message: %w", err)
			}
			c.ch.Width = msg.Width
			c.ch.Height = msg.Height
		}
	}
	c.currentReadMsg = readMsg
	return n, err
}

// Write parses the written bytes as WebSocket message fragment. If the message
// is for stdout or stderr streams, it is written to the configured tsrecorder.
// A message fragment can be incomplete.
func (c *conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	typ := messageType(opcode(b))
	// If we are in process of parsing a message fragment, the received
	// bytes are not structured as a message fragment and can not be used to
	// determine a message fragment.
	if len(c.writeBuf.Bytes()) > 0 { // buffer contains previous incomplete fragment
		typ = c.currentWriteMsg.typ
	}

	if isControlMessage(typ) {
		n, err := c.Conn.Write(b)
		return n, err
	}

	if _, err := c.writeBuf.Write(b); err != nil {
		c.log.Errorf("write: error writing to write buf: %v", err)
		return 0, fmt.Errorf("[unexpected] error writing to internal write buffer: %w", err)
	}

	writeMsg := &message{typ: typ} // start a new message...
	// ... or continue the existing one if it has not been finalized.
	if c.currentWriteMsg != nil && !c.currentWriteMsg.isFinalized {
		writeMsg = c.currentWriteMsg
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
			var err error
			c.writeCastHeaderOnce.Do(func() {
				var j []byte
				j, err = json.Marshal(c.ch)
				if err != nil {
					c.log.Infof("error marhsalling conn: %v", err)
					return
				}
				j = append(j, '\n')
				err = c.rec.WriteCastLine(j)
				if err != nil {
					c.log.Errorf("received error from recorder: %v", err)
				}
			})
			if err != nil {
				return 0, fmt.Errorf("error writing CastHeader: %w", err)
			}
			if err := c.rec.Write(writeMsg.payload); err != nil {
				return 0, fmt.Errorf("error writing message to recorder: %v", err)
			}
		}
	}
	_, err = c.Conn.Write(c.currentWriteMsg.raw)
	if err != nil {
		c.log.Errorf("write: error writing to conn: %v", err)
	}
	return len(b), err
}

func (c *conn) Close() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil
	}
	// TODO: only do this if this is a normal closure rather than the
	// reocrding has failed.
	if c.writeBuf.Len() > 0 {
		c.Conn.Write(c.writeBuf.Bytes())
	}
	c.closed = true
	connCloseErr := c.Conn.Close()
	recCloseErr := c.rec.Close()
	return multierr.New(connCloseErr, recCloseErr)
}

// opcode reads the websocket message opcode that denotes the message type.
// opcode is contained in bits [4-8] of the message.
// https://www.rfc-editor.org/rfc/rfc6455#section-5.2
func opcode(b []byte) int {
	// 0xf = 00001111; b & 00001111 zeroes out bits [0 - 3] of b
	var mask byte = 0xf
	return int(b[0] & mask)
}
