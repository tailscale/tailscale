// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlhttp

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/url"

	"nhooyr.io/websocket"
	"tailscale.com/control/controlbase"
)

// Variant of Dial that tunnels the request over WebSockets, since we cannot do
// bi-directional communication over an HTTP connection when in JS.
func (d *Dialer) Dial(ctx context.Context) (*controlbase.Conn, error) {
	if d.Hostname == "" {
		return nil, errors.New("required Dialer.Hostname empty")
	}

	init, cont, err := controlbase.ClientDeferred(d.MachineKey, d.ControlKey, d.ProtocolVersion)
	if err != nil {
		return nil, err
	}

	wsScheme := "wss"
	host := d.Hostname
	if host == "localhost" {
		wsScheme = "ws"
		host = net.JoinHostPort(host, strDef(d.HTTPPort, "80"))
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
	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	cbConn, err := cont(ctx, netConn)
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return cbConn, nil
}
