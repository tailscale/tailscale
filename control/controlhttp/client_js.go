// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlhttp

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/url"

	"nhooyr.io/websocket"
	"tailscale.com/control/controlbase"
	"tailscale.com/net/wsconn"
)

// Variant of Dial that tunnels the request over WebSockets, since we cannot do
// bi-directional communication over an HTTP connection when in JS.
func (d *Dialer) Dial(ctx context.Context) (*ClientConn, error) {
	if d.Hostname == "" {
		return nil, errors.New("required Dialer.Hostname empty")
	}

	init, cont, err := controlbase.ClientDeferred(d.MachineKey, d.ControlKey, d.ProtocolVersion)
	if err != nil {
		return nil, err
	}

	wsScheme := "wss"
	host := d.Hostname
	// If using a custom control server (on a non-standard port), prefer that.
	// This mirrors the port selection in newNoiseClient from noise.go.
	if d.HTTPPort != "" && d.HTTPPort != "80" && d.HTTPSPort == "443" {
		wsScheme = "ws"
		host = net.JoinHostPort(host, d.HTTPPort)
	}
	wsURL := &url.URL{
		Scheme: wsScheme,
		Host:   host,
		Path:   serverUpgradePath,
		// Can't set HTTP headers on the websocket request, so we have to to send
		// the handshake via an HTTP header.
		RawQuery: url.Values{
			handshakeHeaderName: []string{base64.StdEncoding.EncodeToString(init)},
		}.Encode(),
	}
	wsConn, _, err := websocket.Dial(ctx, wsURL.String(), &websocket.DialOptions{
		Subprotocols: []string{upgradeHeaderValue},
	})
	if err != nil {
		return nil, err
	}
	netConn := wsconn.NetConn(context.Background(), wsConn, websocket.MessageBinary, wsURL.String())
	cbConn, err := cont(ctx, netConn)
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return &ClientConn{Conn: cbConn}, nil
}
