// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"tailscale.com/derp"
)

// fastStartHeader is the header (with value "1") that signals to the HTTP
// server that the DERP HTTP client does not want the HTTP 101 response
// headers and it will begin writing & reading the DERP protocol immediately
// following its HTTP request.
const fastStartHeader = "Derp-Fast-Start"

func Handler(s *derp.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up := strings.ToLower(r.Header.Get("Upgrade"))
		if up != "websocket" && up != "derp" {
			if up != "" {
				log.Printf("Weird upgrade: %q", up)
			}
			http.Error(w, "DERP requires connection upgrade", http.StatusUpgradeRequired)
			return
		}

		fastStart := r.Header.Get(fastStartHeader) == "1"

		h, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "HTTP does not support general TCP support", 500)
			return
		}

		netConn, conn, err := h.Hijack()
		if err != nil {
			log.Printf("Hijack failed: %v", err)
			http.Error(w, "HTTP does not support general TCP support", 500)
			return
		}

		if !fastStart {
			pubKey := s.PublicKey()
			fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: DERP\r\n"+
				"Connection: Upgrade\r\n"+
				"Derp-Version: %v\r\n"+
				"Derp-Public-Key: %s\r\n\r\n",
				derp.ProtocolVersion,
				pubKey.UntypedHexString())
		}

		s.Accept(r.Context(), netConn, conn, netConn.RemoteAddr().String())
	})
}
