// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"log"
	"net"
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
		http.Error(w, "node currently has no tailscale IPs", http.StatusInternalServerError)
	}
}

// runHealthz runs a simple HTTP health endpoint on /healthz, listening on the
// provided address. A containerized tailscale instance is considered healthy if
// it has at least one tailnet IP address.
func runHealthz(addr string, h *healthz) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("error listening on the provided health endpoint address %q: %v", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/healthz", h)
	log.Printf("Running healthcheck endpoint at %s/healthz", addr)
	hs := &http.Server{Handler: mux}

	go func() {
		if err := hs.Serve(lis); err != nil {
			log.Fatalf("failed running health endpoint: %v", err)
		}
	}()
}
