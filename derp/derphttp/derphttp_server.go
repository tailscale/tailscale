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

// Handler returns an http.Handler to be mounted at /derp, serving s.
func Handler(s *derp.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// These are installed both here and in cmd/derper. The check here
		// catches both cmd/derper run with DERP disabled (STUN only mode) as
		// well as DERP being run in tests with derphttp.Handler directly,
		// as netcheck still assumes this replies.
		switch r.URL.Path {
		case "/derp/probe", "/derp/latency-check":
			ProbeHandler(w, r)
			return
		}

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

// ProbeHandler is the endpoint that clients without UDP access (including js/wasm) hit to measure
// DERP latency, as a replacement for UDP STUN queries.
func ProbeHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "HEAD", "GET":
		w.Header().Set("Access-Control-Allow-Origin", "*")
	default:
		http.Error(w, "bogus probe method", http.StatusMethodNotAllowed)
	}
}

// ServeNoContent generates the /generate_204 response used by Tailscale's
// captive portal detection.
func ServeNoContent(w http.ResponseWriter, r *http.Request) {
	if challenge := r.Header.Get(NoContentChallengeHeader); challenge != "" {
		badChar := strings.IndexFunc(challenge, func(r rune) bool {
			return !isChallengeChar(r)
		}) != -1
		if len(challenge) <= 64 && !badChar {
			w.Header().Set(NoContentResponseHeader, "response "+challenge)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func isChallengeChar(c rune) bool {
	// Semi-randomly chosen as a limited set of valid characters
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
		('0' <= c && c <= '9') ||
		c == '.' || c == '-' || c == '_'
}

const (
	NoContentChallengeHeader = "X-Tailscale-Challenge"
	NoContentResponseHeader  = "X-Tailscale-Response"
)
