// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"regexp"

	"tailscale.com/derp"
)

var IPsanitizer = regexp.MustCompile("[^][a-zA-Z0-9:.]+")

// Handler returns an http.Handler to be mounted at /derp, serving s.
func Handler(s *Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

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

		fastStart := r.Header.Get(derp.FastStartHeader) == "1"

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

		if v := r.Header.Get(derp.IdealNodeHeader); v != "" {
			ctx = IdealNodeContextKey.WithValue(ctx, v)
		}

		var remote_addr = netConn.RemoteAddr().String()

		if (s.acceptProxy != "") && strings.HasPrefix(remote_addr, s.acceptProxy) {
			var header_addr = IPsanitizer.ReplaceAllString(r.Header.Get("X-Real-IP"), "")

			if (header_addr != "") {
				// the port is only used as a key to index the connection.  there is
				// a chance that two connections from the same remote, one from a proxy,
				// and another direct, may have the same "remote" port (one, the actual
				// source port on the derp client, the other the source port used by the
				// proxy).

				// ports are 16 bits, so that chance is 1 in ~ 2**8, which is
				// frustratingly likely,  please don't connect to derper that way!
				remote_addr = header_addr + remote_addr[len(s.acceptProxy)-1:len(remote_addr)]
			}
		}

		s.Accept(ctx, netConn, conn, remote_addr)
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
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, no-transform, max-age=0")
	w.WriteHeader(http.StatusNoContent)
}

func isChallengeChar(c rune) bool {
	// Semi-randomly chosen as a limited set of valid characters
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') ||
		('0' <= c && c <= '9') ||
		c == '.' || c == '-' || c == '_' || c == ':'
}

const (
	NoContentChallengeHeader = "X-Tailscale-Challenge"
	NoContentResponseHeader  = "X-Tailscale-Response"
)
