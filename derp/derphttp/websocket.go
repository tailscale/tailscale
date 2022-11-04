// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || js

package derphttp

import (
	"context"
	"log"
	"net"

	"nhooyr.io/websocket"
	"tailscale.com/net/wsconn"
)

func init() {
	dialWebsocketFunc = dialWebsocket
}

func dialWebsocket(ctx context.Context, urlStr string) (net.Conn, error) {
	c, res, err := websocket.Dial(ctx, urlStr, &websocket.DialOptions{
		Subprotocols: []string{"derp"},
	})
	if err != nil {
		log.Printf("websocket Dial: %v, %+v", err, res)
		return nil, err
	}
	log.Printf("websocket: connected to %v", urlStr)
	netConn := wsconn.NetConn(context.Background(), c, websocket.MessageBinary)
	return netConn, nil
}
