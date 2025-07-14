// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package spdy contains functionality for parsing SPDY streaming sessions. This
// is used for 'kubectl exec/attach' session recording.
package spdy

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"tailscale.com/k8s-operator/sessionrecording/tsrecorder"
	"tailscale.com/sessionrecording"
)

// New wraps the provided network connection and returns a connection whose reads and writes will get triggered as data is received on the hijacked connection.
// The connection must be a hijacked connection for a 'kubectl exec/attach' session using SPDY.
// The hijacked connection is used to transmit SPDY streams between Kubernetes client ('kubectl') and the destination container.
// Data read from the underlying network connection is data sent via one of the SPDY streams from the client to the container.
// Data written to the underlying connection is data sent from the container to the client.
// We parse the data and send everything for the stdout/stderr streams to the configured tsrecorder as an asciinema recording with the provided header.
// https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/4006-transition-spdy-to-websockets#background-remotecommand-subprotocol
func New(ctx context.Context, nc net.Conn, rec *tsrecorder.Client, ch sessionrecording.CastHeader, hasTerm bool, log *zap.SugaredLogger) (net.Conn, error) {
	lc := &conn{
		Conn:                  nc,
		ctx:                   ctx,
		rec:                   rec,
		ch:                    ch,
		log:                   log,
		hasTerm:               hasTerm,
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

// conn is a wrapper around net.Conn. It reads the bytestream for a 'kubectl
// exec/attach' session streamed using SPDY protocol, sends session recording data to
// the configured recorder and forwards the raw bytes to the original
// destination.
type conn struct {
	net.Conn
	ctx context.Context
	// rec knows how to send data written to it to a tsrecorder instance.
	rec *tsrecorder.Client

	stdoutStreamID atomic.Uint32
	stderrStreamID atomic.Uint32
	resizeStreamID atomic.Uint32

	wmu    sync.Mutex // sequences writes
	closed bool

	rmu sync.Mutex // sequences reads

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

	// ch is the asciinema CastHeader for the current session.
	// https://docs.asciinema.org/manual/asciicast/v2/#header
	ch sessionrecording.CastHeader
	// writeCastHeaderOnce is used to ensure CastHeader gets sent to tsrecorder once.
	writeCastHeaderOnce sync.Once
	hasTerm             bool // whether the session had TTY attached
	// initialCastHeaderSent is a channel to ensure that the cast
	// header is the first thing that is streamed to the session recorder.
	// Otherwise the stream will fail.
	initialCastHeaderSent chan struct{}

	zlibReqReader zlibReader
	// writeBuf is used to store data written to the connection that has not
	// yet been parsed as SPDY frames.
	writeBuf bytes.Buffer
	// readBuf is used to store data read from the connection that has not
	// yet been parsed as SPDY frames.
	readBuf bytes.Buffer
	log     *zap.SugaredLogger
}

// Read reads bytes from the original connection and parses them as SPDY frames.
// If the frame is a data frame for resize stream, sends resize message to the
// recorder. If the frame is a SYN_STREAM control frame that starts stdout,
// stderr or resize stream, store the stream ID.
func (c *conn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, fmt.Errorf("error reading from connection: %w", err)
	}
	c.readBuf.Write(b[:n])

	var sf spdyFrame
	ok, err := sf.Parse(c.readBuf.Bytes(), c.log)
	if err != nil {
		return 0, fmt.Errorf("error parsing data read from connection: %w", err)
	}
	if !ok {
		// The parsed data in the buffer will be processed together with
		// the new data on the next call to Read.
		return n, nil
	}
	c.readBuf.Next(len(sf.Raw)) // advance buffer past the parsed frame

	if !sf.Ctrl && c.hasTerm { // data frame
		switch sf.StreamID {
		case c.resizeStreamID.Load():

			var msg spdyResizeMsg
			if err = json.Unmarshal(sf.Payload, &msg); err != nil {
				return 0, fmt.Errorf("error umarshalling resize msg: %w", err)
			}
			c.ch.Width = msg.Width
			c.ch.Height = msg.Height

			// If this is initial resize message, the width and
			// height will be sent in the CastHeader. If this is a
			// subsequent resize message, we need to send asciinema
			// resize message.
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
				if err := c.rec.WriteResize(c.ch.Height, c.ch.Width); err != nil {
					return 0, fmt.Errorf("error writing resize message: %w", err)
				}
			}
		}
		return n, nil
	}
	// We always want to parse the headers, even if we don't care about the
	// frame, as we need to advance the zlib reader otherwise we will get
	// garbage.
	header, err := sf.parseHeaders(&c.zlibReqReader, c.log)
	if err != nil {
		return 0, fmt.Errorf("error parsing frame headers: %w", err)
	}
	if sf.Type == SYN_STREAM {
		c.storeStreamID(sf, header)
	}
	return n, nil
}

// Write forwards the raw data of the latest parsed SPDY frame to the original
// destination. If the frame is an SPDY data frame, it also sends the payload to
// the connected session recorder.
func (c *conn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.writeBuf.Write(b)

	var sf spdyFrame
	ok, err := sf.Parse(c.writeBuf.Bytes(), c.log)
	if err != nil {
		return 0, fmt.Errorf("error parsing data: %w", err)
	}
	if !ok {
		// The parsed data in the buffer will be processed together with
		// the new data on the next call to Write.
		return len(b), nil
	}
	c.writeBuf.Next(len(sf.Raw)) // advance buffer past the parsed frame

	// If this is a stdout or stderr data frame, send its payload to the
	// session recorder.
	if !sf.Ctrl {
		switch sf.StreamID {
		case c.stdoutStreamID.Load(), c.stderrStreamID.Load():
			// we must wait for confirmation that the initial cast header was sent before proceeding with any more writes
			select {
			case <-c.ctx.Done():
				return 0, c.ctx.Err()
			case <-c.initialCastHeaderSent:
				if err := c.rec.WriteOutput(sf.Payload); err != nil {
					return 0, fmt.Errorf("error sending payload to session recorder: %w", err)
				}
			}
		}
	}
	// Forward the whole frame to the original destination.
	_, err = c.Conn.Write(sf.Raw) // send to net.Conn
	return len(b), err
}

func (c *conn) Close() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil
	}
	c.writeBuf.Reset()
	c.closed = true
	err := c.Conn.Close()
	c.rec.Close()
	return err
}

// storeStreamID parses SYN_STREAM SPDY control frame and updates
// conn to store the newly created stream's ID if it is one of
// the stream types we care about. Storing stream_id:stream_type mapping allows
// us to parse received data frames (that have stream IDs) differently depening
// on which stream they belong to (i.e send data frame payload for stdout stream
// to session recorder).
func (c *conn) storeStreamID(sf spdyFrame, header http.Header) {
	const (
		streamTypeHeaderKey = "Streamtype"
	)
	id := binary.BigEndian.Uint32(sf.Payload[0:4])
	switch header.Get(streamTypeHeaderKey) {
	case corev1.StreamTypeStdout:
		c.stdoutStreamID.Store(id)
	case corev1.StreamTypeStderr:
		c.stderrStreamID.Store(id)
	case corev1.StreamTypeResize:
		c.resizeStreamID.Store(id)
	}
}

type spdyResizeMsg struct {
	Width  int `json:"width"`
	Height int `json:"height"`
}
