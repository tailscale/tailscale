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

	"tailscale.com/control/controlbase"
	"tailscale.com/net/netutil"
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
