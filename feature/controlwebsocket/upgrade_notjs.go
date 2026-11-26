// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

package controlwebsocket

import (
	"context"
	"net"
	"net/http"
	"net/url"

	"github.com/coder/websocket"
	"tailscale.com/control/controlhttp"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/feature"
	"tailscale.com/net/wsconn"
)

func init() {
	if !feature.Register("controlwebsocket") {
		return
	}
	controlhttp.HookUpgradeWebsocket.Set(upgrade)
}

// upgrade does a WebSocket handshake with the control server at urlStr
// using hc, which controlhttp set up with its DNS, proxy and TLS settings.
// It returns a net.Conn that carries the control protocol in binary
// WebSocket messages.
func upgrade(ctx context.Context, hc *http.Client, urlStr string) (net.Conn, error) {
	wc, _, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{
		HTTPClient:   hc,
		Subprotocols: []string{controlhttpcommon.UpgradeHeaderValue},
		// Noise messages don't compress.
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	// Leave the handshake in the query out of the conn's remote address.
	remoteAddr := urlStr
	if u, err := url.Parse(urlStr); err == nil {
		remoteAddr = u.Host
	}
	// The conn outlives the handshake, so don't bind it to ctx.
	return wsconn.NetConn(context.Background(), wc, websocket.MessageBinary, remoteAddr), nil
}
