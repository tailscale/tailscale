// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"log"
	"net/http"
	"sync"
)

// healthz is a simple health check server, if enabled it returns 200 OK if
// this tailscale node currently has at least one tailnet IP address else
// returns 503.
type healthz struct {
	sync.Mutex
	hasAddrs bool
}

func (h *healthz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Lock()
	defer h.Unlock()

	if h.hasAddrs {
		w.Write([]byte("ok"))
	} else {
		http.Error(w, "node currently has no tailscale IPs", http.StatusServiceUnavailable)
	}
}

func (h *healthz) update(healthy bool) {
	h.Lock()
	defer h.Unlock()

	if h.hasAddrs != healthy {
		log.Println("Setting healthy", healthy)
	}
	h.hasAddrs = healthy
}

// healthHandlers registers a simple health handler at /healthz.
// A containerized tailscale instance is considered healthy if
// it has at least one tailnet IP address.
func healthHandlers(mux *http.ServeMux) *healthz {
	h := &healthz{}
	mux.Handle("GET /healthz", h)
	return h
}
