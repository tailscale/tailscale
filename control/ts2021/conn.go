// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ts2021 handles the details of the Tailscale 2021 control protocol
// that are after (above) the Noise layer. In particular, the
// "tailcfg.EarlyNoise" message and the subsequent HTTP/2 connection.
package ts2021

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/tailcfg"
)

// Conn is a wrapper around controlbase.Conn.
//
// It allows attaching an ID to a connection to allow cleaning up references in
// the pool when the connection is closed, properly handles an optional "early
// payload" that's sent prior to beginning the HTTP/2 session, and provides a
// way to return a connection to a pool when the connection is closed.
type Conn struct {
	*controlbase.Conn
	id      int
	onClose func(int)
	h2cc    *http2.ClientConn

	readHeaderOnce    sync.Once     // guards init of reader field
	reader            io.Reader     // (effectively Conn.Reader after header)
	earlyPayloadReady chan struct{} // closed after earlyPayload is set (including set to nil)
	earlyPayload      *tailcfg.EarlyNoise
	earlyPayloadErr   error
}

// New creates a new Conn that wraps the given controlbase.Conn.
//
// h2t is the HTTP/2 transport to use for the connection; a new
// http2.ClientConn will be created that reads from the returned Conn.
//
// connID should be a unique ID for this connection. When the Conn is closed,
// the onClose function will be called with the connID if it is non-nil.
func New(conn *controlbase.Conn, h2t *http2.Transport, connID int, onClose func(int)) (*Conn, error) {
	ncc := &Conn{
		Conn:              conn,
		id:                connID,
		onClose:           onClose,
		earlyPayloadReady: make(chan struct{}),
	}
	h2cc, err := h2t.NewClientConn(ncc)
	if err != nil {
		return nil, err
	}
	ncc.h2cc = h2cc
	return ncc, nil
}

// RoundTrip implements the http.RoundTripper interface.
func (c *Conn) RoundTrip(r *http.Request) (*http.Response, error) {
	return c.h2cc.RoundTrip(r)
}

// GetEarlyPayload waits for the early Noise payload to arrive.
// It may return (nil, nil) if the server begins HTTP/2 without one.
//
// It is safe to call this multiple times; all callers will block until the
// early Noise payload is ready (if any) and will return the same result for
// the lifetime of the Conn.
func (c *Conn) GetEarlyPayload(ctx context.Context) (*tailcfg.EarlyNoise, error) {
	select {
	case <-c.earlyPayloadReady:
		return c.earlyPayload, c.earlyPayloadErr
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// CanTakeNewRequest reports whether the underlying HTTP/2 connection can take
// a new request, meaning it has not been closed or received or sent a GOAWAY.
func (c *Conn) CanTakeNewRequest() bool {
	return c.h2cc.CanTakeNewRequest()
}

// The first 9 bytes from the server to client over Noise are either an HTTP/2
// settings frame (a normal HTTP/2 setup) or, as we added later, an "early payload"
// header that's also 9 bytes long: 5 bytes (EarlyPayloadMagic) followed by 4 bytes
// of length. Then that many bytes of JSON-encoded tailcfg.EarlyNoise.
// The early payload is optional. Some servers may not send it.
const (
	hdrLen = 9 // http2 frame header size; also size of our early payload size header
)

// EarlyPayloadMagic is the 5-byte magic prefix that indicates an early payload.
const EarlyPayloadMagic = "\xff\xff\xffTS"

// returnErrReader is an io.Reader that always returns an error.
type returnErrReader struct {
	err error // the error to return
}

func (r returnErrReader) Read([]byte) (int, error) { return 0, r.err }

// Read is basically the same as controlbase.Conn.Read, but it first reads the
// "early payload" header from the server which may or may not be present,
// depending on the server.
func (c *Conn) Read(p []byte) (n int, err error) {
	c.readHeaderOnce.Do(c.readHeader)
	return c.reader.Read(p)
}

// readHeader reads the optional "early payload" from the server that arrives
// after the Noise handshake but before the HTTP/2 session begins.
//
// readHeader is responsible for reading the header (if present), initializing
// c.earlyPayload, closing c.earlyPayloadReady, and initializing c.reader for
// future reads.
func (c *Conn) readHeader() {
	defer close(c.earlyPayloadReady)

	setErr := func(err error) {
		c.reader = returnErrReader{err}
		c.earlyPayloadErr = err
	}

	var hdr [hdrLen]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		setErr(err)
		return
	}
	if string(hdr[:len(EarlyPayloadMagic)]) != EarlyPayloadMagic {
		// No early payload. We have to return the 9 bytes read we already
		// consumed.
		c.reader = io.MultiReader(bytes.NewReader(hdr[:]), c.Conn)
		return
	}
	epLen := binary.BigEndian.Uint32(hdr[len(EarlyPayloadMagic):])
	if epLen > 10<<20 {
		setErr(errors.New("invalid early payload length"))
		return
	}
	payBuf := make([]byte, epLen)
	if _, err := io.ReadFull(c.Conn, payBuf); err != nil {
		setErr(err)
		return
	}
	if err := json.Unmarshal(payBuf, &c.earlyPayload); err != nil {
		setErr(err)
		return
	}
	c.reader = c.Conn
}

// Close closes the connection.
func (c *Conn) Close() error {
	if err := c.Conn.Close(); err != nil {
		return err
	}
	if c.onClose != nil {
		c.onClose(c.id)
	}
	return nil
}
