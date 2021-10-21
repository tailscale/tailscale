// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"expvar"
	"log"
	"net/http"
	"strings"

	"nhooyr.io/websocket"
	"tailscale.com/derp"
	"tailscale.com/derp/wsconn"
)

var counterWebSocketAccepts = expvar.NewInt("derp_websocket_accepts")

// addWebSocketSupport returns a Handle wrapping base that adds WebSocket server support.
func addWebSocketSupport(s *derp.Server, base http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := strings.ToLower(r.Header.Get("Upgrade"))

		// Very early versions of Tailscale set "Upgrade: WebSocket" but didn't actually
		// speak WebSockets (they still assumed DERP's binary framining). So to distinguish
		// clients that actually want WebSockets, look for an explicit "derp" subprotocol.
		if up != "websocket" || !strings.Contains(r.Header.Get("Sec-Websocket-Protocol"), "derp") {
			base.ServeHTTP(w, r)
			return
		}

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:   []string{"derp"},
			OriginPatterns: []string{"*"},
		})
		if err != nil {
			log.Printf("websocket.Accept: %v", err)
			return
		}
		defer c.Close(websocket.StatusInternalError, "closing")
		if c.Subprotocol() != "derp" {
			c.Close(websocket.StatusPolicyViolation, "client must speak the derp subprotocol")
			return
		}
		counterWebSocketAccepts.Add(1)
		wc := wsconn.New(c)
		brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
		s.Accept(wc, brw, r.RemoteAddr)
	})
}
