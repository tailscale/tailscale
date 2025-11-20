// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package connectproxy contains some CONNECT proxy code.
package connectproxy

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"tailscale.com/net/netx"
	"tailscale.com/types/logger"
)

// Handler is an HTTP CONNECT proxy handler.
type Handler struct {
	// Dial, if non-nil, is an alternate dialer to use
	// instead of the default dialer.
	Dial netx.DialFunc

	// Logf, if non-nil, is an alterate logger to
	// use instead of log.Printf.
	Logf logger.Logf

	// Check, if non-nil, validates the CONNECT target.
	Check func(hostPort string) error
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != "CONNECT" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dial := h.Dial
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	logf := h.Logf
	if logf == nil {
		logf = log.Printf
	}

	hostPort := r.RequestURI
	if h.Check != nil {
		if err := h.Check(hostPort); err != nil {
			logf("CONNECT target %q not allowed: %v", hostPort, err)
			http.Error(w, "Invalid CONNECT target", http.StatusForbidden)
			return
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	back, err := dial(ctx, "tcp", hostPort)
	if err != nil {
		logf("error CONNECT dialing %v: %v", hostPort, err)
		http.Error(w, "Connect failure", http.StatusBadGateway)
		return
	}
	defer back.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT hijack unavailable", http.StatusInternalServerError)
		return
	}
	c, br, err := hj.Hijack()
	if err != nil {
		logf("CONNECT hijack: %v", err)
		return
	}
	defer c.Close()

	io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(c, back)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(back, br)
		errc <- err
	}()
	<-errc
}
