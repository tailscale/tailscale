// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlhttp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/control/controlbase"
	"tailscale.com/net/netutil"
	"tailscale.com/net/wsconn"
	"tailscale.com/types/key"
)

// AcceptHTTP upgrades the HTTP request given by w and r into a Tailscale
// control protocol base transport connection.
//
// AcceptHTTP always writes an HTTP response to w. The caller must not attempt
// their own response after calling AcceptHTTP.
//
// earlyWrite optionally specifies a func to write to the noise connection
// (encrypted). It receives the negotiated version and a writer to write to, if
// desired.
func AcceptHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, private key.MachinePrivate, earlyWrite func(protocolVersion int, w io.Writer) error) (*controlbase.Conn, error) {
	return acceptHTTP(ctx, w, r, private, earlyWrite)
}

func acceptHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, private key.MachinePrivate, earlyWrite func(protocolVersion int, w io.Writer) error) (_ *controlbase.Conn, retErr error) {
	next := strings.ToLower(r.Header.Get("Upgrade"))
	if next == "" {
		http.Error(w, "missing next protocol", http.StatusBadRequest)
		return nil, errors.New("no next protocol in HTTP request")
	}
	if next == "websocket" {
		return acceptWebsocket(ctx, w, r, private)
	}
	if next != upgradeHeaderValue {
		http.Error(w, "unknown next protocol", http.StatusBadRequest)
		return nil, fmt.Errorf("client requested unhandled next protocol %q", next)
	}

	initB64 := r.Header.Get(handshakeHeaderName)
	if initB64 == "" {
		http.Error(w, "missing Tailscale handshake header", http.StatusBadRequest)
		return nil, errors.New("no tailscale handshake header in HTTP request")
	}
	init, err := base64.StdEncoding.DecodeString(initB64)
	if err != nil {
		http.Error(w, "invalid tailscale handshake header", http.StatusBadRequest)
		return nil, fmt.Errorf("decoding base64 handshake header: %v", err)
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "make request over HTTP/1", http.StatusBadRequest)
		return nil, errors.New("can't hijack client connection")
	}

	w.Header().Set("Upgrade", upgradeHeaderValue)
	w.Header().Set("Connection", "upgrade")
	w.WriteHeader(http.StatusSwitchingProtocols)

	conn, brw, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("hijacking client connection: %w", err)
	}

	defer func() {
		if retErr != nil {
			conn.Close()
		}
	}()

	if err := brw.Flush(); err != nil {
		return nil, fmt.Errorf("flushing hijacked HTTP buffer: %w", err)
	}
	conn = netutil.NewDrainBufConn(conn, brw.Reader)

	cwc := newWriteCorkingConn(conn)

	nc, err := controlbase.Server(ctx, cwc, private, init)
	if err != nil {
		return nil, fmt.Errorf("noise handshake failed: %w", err)
	}

	if earlyWrite != nil {
		if deadline, ok := ctx.Deadline(); ok {
			if err := conn.SetDeadline(deadline); err != nil {
				return nil, fmt.Errorf("setting conn deadline: %w", err)
			}
			defer conn.SetDeadline(time.Time{})
		}
		if err := earlyWrite(nc.ProtocolVersion(), nc); err != nil {
			return nil, err
		}
	}

	if err := cwc.uncork(); err != nil {
		return nil, err
	}

	return nc, nil
}

// acceptWebsocket upgrades a WebSocket connection (from a client that cannot
// speak HTTP) to a Tailscale control protocol base transport connection.
func acceptWebsocket(ctx context.Context, w http.ResponseWriter, r *http.Request, private key.MachinePrivate) (*controlbase.Conn, error) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:   []string{upgradeHeaderValue},
		OriginPatterns: []string{"*"},
		// Disable compression because we transmit Noise messages that are not
		// compressible.
		// Additionally, Safari has a broken implementation of compression
		// (see https://github.com/nhooyr/websocket/issues/218) that makes
		// enabling it actively harmful.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("Could not accept WebSocket connection %v", err)
	}
	if c.Subprotocol() != upgradeHeaderValue {
		c.Close(websocket.StatusPolicyViolation, "client must speak the control subprotocol")
		return nil, fmt.Errorf("Unexpected subprotocol %q", c.Subprotocol())
	}
	if err := r.ParseForm(); err != nil {
		c.Close(websocket.StatusPolicyViolation, "Could not parse parameters")
		return nil, fmt.Errorf("parse query parameters: %v", err)
	}
	initB64 := r.Form.Get(handshakeHeaderName)
	if initB64 == "" {
		c.Close(websocket.StatusPolicyViolation, "missing Tailscale handshake parameter")
		return nil, errors.New("no tailscale handshake parameter in HTTP request")
	}
	init, err := base64.StdEncoding.DecodeString(initB64)
	if err != nil {
		c.Close(websocket.StatusPolicyViolation, "invalid tailscale handshake parameter")
		return nil, fmt.Errorf("decoding base64 handshake parameter: %v", err)
	}

	conn := wsconn.NetConn(ctx, c, websocket.MessageBinary, r.RemoteAddr)
	nc, err := controlbase.Server(ctx, conn, private, init)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("noise handshake failed: %w", err)
	}

	return nc, nil
}

// corkConn is a net.Conn wrapper that initially buffers all writes until uncork
// is called. If the conn is corked and a Read occurs, the Read will flush any
// buffered (corked) write.
//
// Until uncorked, Read/Write/uncork may be not called concurrently.
//
// Deadlines still work, but a corked write ignores deadlines until a Read or
// uncork goes to do that Write.
//
// Use newWriteCorkingConn to create one.
type corkConn struct {
	net.Conn
	corked bool
	buf    []byte // corked data
}

func newWriteCorkingConn(c net.Conn) *corkConn {
	return &corkConn{Conn: c, corked: true}
}

func (c *corkConn) Write(b []byte) (int, error) {
	if c.corked {
		c.buf = append(c.buf, b...)
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *corkConn) Read(b []byte) (int, error) {
	if c.corked {
		if err := c.flush(); err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(b)
}

// uncork flushes any buffered data and uncorks the connection so future Writes
// don't buffer. It may not be called concurrently with reads or writes and
// may only be called once.
func (c *corkConn) uncork() error {
	if !c.corked {
		panic("usage error; uncork called twice") // worth panicking to catch misuse
	}
	err := c.flush()
	c.corked = false
	return err
}

func (c *corkConn) flush() error {
	if len(c.buf) == 0 {
		return nil
	}
	_, err := c.Conn.Write(c.buf)
	c.buf = nil
	return err
}
