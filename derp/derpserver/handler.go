// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derpserver

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime/debug"
	"strings"

	"tailscale.com/derp"
)

// Handler returns an http.Handler to be mounted at /derp, serving s.
func Handler(s *Server) http.Handler {
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

		fastStart := r.Header.Get(derp.FastStartHeader) == "1"

		h, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "HTTP does not support general TCP support", 500)
			return
		}

		netConn, brw, err := h.Hijack()
		if err != nil {
			log.Printf("Hijack failed: %v", err)
			http.Error(w, "HTTP does not support general TCP support", 500)
			return
		}

		if !fastStart {
			pubKey := s.PublicKey()
			// Write directly to netConn, not brw: the connection is
			// handed off to Accept without brw's write half below.
			if _, err := fmt.Fprintf(netConn, "HTTP/1.1 101 Switching Protocols\r\n"+
				"Upgrade: DERP\r\n"+
				"Connection: Upgrade\r\n"+
				"Derp-Version: %v\r\n"+
				"Derp-Public-Key: %s\r\n\r\n",
				derp.ProtocolVersion,
				pubKey.UntypedHexString()); err != nil {
				netConn.Close()
				return
			}
		}

		// The request context is unusable past this point: net/http
		// cancels it when this handler returns. Build a fresh one,
		// copying the only value the DERP server reads from it.
		ctx := context.Background()
		if v := r.Header.Get(derp.IdealNodeHeader); v != "" {
			ctx = IdealNodeContextKey.WithValue(ctx, v)
		}

		// Replace the hijacked connection's 4KB bufio.Reader with a
		// smaller one; DERP frame payloads are read with io.ReadFull,
		// which bypasses the buffer for reads larger than it. The
		// hijacked reader can only be dropped if it holds no bytes,
		// but it's always empty in practice: clients don't send any
		// DERP frames until they've received the server's key.
		br := brw.Reader
		if br.Buffered() == 0 {
			br = bufio.NewReaderSize(netConn, 1<<10)
		}
		// The nil Writer makes Accept's internal lazyBufioWriter pull
		// a pooled buffer on demand rather than retaining one per
		// connection.
		derpBRW := bufio.NewReadWriter(br, nil)

		// Serve the DERP connection on its own goroutine and return
		// from this handler so the net/http server state (its conn,
		// bufio buffers, this Request and its headers) can be garbage
		// collected instead of being pinned for the lifetime of the
		// connection.
		go serveHijackedConn(ctx, s, netConn, derpBRW)
	})
}

// serveHijackedConn serves a DERP connection hijacked from the HTTP
// server by [Handler], blocking until the connection is closed. It
// runs as its own goroutine, no longer under net/http's per-connection
// panic recovery, so it recovers panics itself to keep one bad
// connection from taking down the whole process.
func serveHijackedConn(ctx context.Context, s *Server, netConn net.Conn, brw *bufio.ReadWriter) {
	defer func() {
		if e := recover(); e != nil {
			log.Printf("derp: panic serving %v: %v\n%s", netConn.RemoteAddr(), e, debug.Stack())
			netConn.Close()
		}
	}()
	s.Accept(ctx, netConn, brw, netConn.RemoteAddr().String())
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
