// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"

	"tailscale.com/derp"
)

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

		s.Accept(ctx, netConn, conn, RealClientAddr(r, s.AcceptProxyHeaders()))
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

// RealClientAddr returns the real client address from r.
//
// If acceptProxyHeaders is true and r.RemoteAddr is a loopback address,
// the client IP is taken from X-Real-IP (preferred) or the left-most
// entry of X-Forwarded-For (the original client by convention). The port
// is taken from r.RemoteAddr — the reverse proxy's upstream connection
// port — since the original client port is not preserved in either
// header. This keeps each returned address unique per connection and
// lets operators correlate it with the proxy's access log.
//
// Otherwise, or if the headers are absent or unparseable, r.RemoteAddr
// is returned unchanged.
func RealClientAddr(r *http.Request, acceptProxyHeaders bool) string {
	if !acceptProxyHeaders {
		return r.RemoteAddr
	}
	addrPort, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !addrPort.Addr().IsLoopback() {
		return r.RemoteAddr
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		if ip, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			return netip.AddrPortFrom(ip, addrPort.Port()).String()
		}
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		first, _, _ := strings.Cut(v, ",")
		if ip, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
			return netip.AddrPortFrom(ip, addrPort.Port()).String()
		}
	}
	return r.RemoteAddr
}

const (
	NoContentChallengeHeader = "X-Tailscale-Challenge"
	NoContentResponseHeader  = "X-Tailscale-Response"
)
