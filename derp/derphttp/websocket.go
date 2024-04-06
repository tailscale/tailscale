// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || windows || darwin || js

package derphttp

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"

	"nhooyr.io/websocket"
	"tailscale.com/net/wsconn"
)

func init() {
	dialWebsocketFunc = dialWebsocket
}

func dialWebsocket(ctx context.Context, urlStr string, tlsConfig *tls.Config) (net.Conn, error) {
	c, res, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		Subprotocols: []string{"derp"},
	})
	if err != nil {
		log.Printf("websocket Dial: %v, %+v", err, res)
		return nil, err
	}
	log.Printf("websocket: connected to %v", urlStr)
	netConn := wsconn.NetConn(context.Background(), c, websocket.MessageBinary, urlStr)
	return netConn, nil
}
