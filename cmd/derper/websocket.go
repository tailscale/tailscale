// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bufio"
	"expvar"
	"log"
	"net/http"
	"strings"

	"github.com/coder/websocket"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/wsconn"
)

var counterWebSocketAccepts = expvar.NewInt("derp_websocket_accepts")

// addWebSocketSupport returns a Handle wrapping base that adds WebSocket server support.
func addWebSocketSupport(s *derpserver.Server, base http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := strings.ToLower(r.Header.Get("Upgrade"))

		// Very early versions of Tailscale set "Upgrade: WebSocket" but didn't actually
		// speak WebSockets (they still assumed DERP's binary framing). So to distinguish
		// clients that actually want WebSockets, look for an explicit "derp" subprotocol.
		if up != "websocket" || !strings.Contains(r.Header.Get("Sec-Websocket-Protocol"), "derp") {
			base.ServeHTTP(w, r)
			return
		}

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:   []string{"derp"},
			OriginPatterns: []string{"*"},
			// Disable compression because we transmit WireGuard messages that
			// are not compressible.
			// Additionally, Safari has a broken implementation of compression
			// (see https://github.com/nhooyr/websocket/issues/218) that makes
			// enabling it actively harmful.
			CompressionMode: websocket.CompressionDisabled,
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
		wc := wsconn.NetConn(r.Context(), c, websocket.MessageBinary, r.RemoteAddr)
		brw := bufio.NewReadWriter(bufio.NewReader(wc), bufio.NewWriter(wc))
		s.Accept(r.Context(), wc, brw, r.RemoteAddr)
	})
}
