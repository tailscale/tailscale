// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlhttp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"nhooyr.io/websocket"
	"tailscale.com/control/controlbase"
	"tailscale.com/net/netutil"
	"tailscale.com/net/wsconn"
	"tailscale.com/types/key"
)

// AcceptHTTP upgrades the HTTP request given by w and r into a
// Tailscale control protocol base transport connection.
//
// AcceptHTTP always writes an HTTP response to w. The caller must not
// attempt their own response after calling AcceptHTTP.
func AcceptHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, private key.MachinePrivate) (*controlbase.Conn, error) {
	next := r.Header.Get("Upgrade")
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
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("flushing hijacked HTTP buffer: %w", err)
	}
	conn = netutil.NewDrainBufConn(conn, brw.Reader)

	nc, err := controlbase.Server(ctx, conn, private, init)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("noise handshake failed: %w", err)
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

	conn := wsconn.NetConn(ctx, c, websocket.MessageBinary)
	nc, err := controlbase.Server(ctx, conn, private, init)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("noise handshake failed: %w", err)
	}

	return nc, nil
}
