// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlhttp

import (
	"context"
	"encoding/base64"
	"net"
	"net/url"

	"nhooyr.io/websocket"
	"tailscale.com/control/controlbase"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/wsconn"
	"tailscale.com/types/key"
)

// Variant of Dial that tunnels the request over WebScokets, since we cannot do
// bi-directional communication over an HTTP connection when in JS.
func Dial(ctx context.Context, addr string, machineKey key.MachinePrivate, controlKey key.MachinePublic, protocolVersion uint16, dialer dnscache.DialContextFunc) (*controlbase.Conn, error) {
	init, cont, err := controlbase.ClientDeferred(machineKey, controlKey, protocolVersion)
	if err != nil {
		return nil, err
	}

	host, addr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	wsURL := &url.URL{
		Scheme: "ws",
		Host:   net.JoinHostPort(host, addr),
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
	netConn := wsconn.New(wsConn)
	cbConn, err := cont(ctx, netConn)
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return cbConn, nil

}
