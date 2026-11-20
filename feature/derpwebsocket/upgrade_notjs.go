// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package derpwebsocket

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/coder/websocket"
	"tailscale.com/derp/derphttp"
	"tailscale.com/feature"
	"tailscale.com/net/wsconn"
)

func init() {
	if !feature.Register("derpwebsocket") {
		return
	}
	derphttp.HookUpgradeWebsocket.Set(upgrade)
}

// upgrade does a WebSocket handshake with the DERP server at urlStr over
// conn, which derphttp has already dialed (via any HTTP proxy) and, for
// https URLs, TLS-wrapped. It returns a net.Conn that carries DERP frames
// in binary WebSocket messages.
func upgrade(ctx context.Context, conn net.Conn, urlStr string) (net.Conn, error) {
	var used atomic.Bool
	dial := func(context.Context, string, string) (net.Conn, error) {
		if used.Swap(true) {
			return nil, errors.New("DERP websocket handshake tried to dial a second connection")
		}
		return conn, nil
	}
	hc := &http.Client{
		Transport: &http.Transport{
			DialContext:    dial, // for http URLs
			DialTLSContext: dial, // for https URLs; conn is already TLS
		},
	}
	wc, _, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{
		HTTPClient:   hc,
		Subprotocols: []string{"derp"},
		// WireGuard packets don't compress.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	return wsconn.NetConn(context.Background(), wc, websocket.MessageBinary, urlStr), nil
}
