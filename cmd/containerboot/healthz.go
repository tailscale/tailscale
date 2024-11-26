// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/ipn/ipnstate"
)

// healthz is a simple health check server, if enabled it returns 200 OK if this tailscale device can be considered
// healthy (running, connected to control plane, has tailnet IPs) else returns 503.
type healthz struct {
	lc *tailscale.LocalClient
}

func (h *healthz) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Most health checks will have their own timeout, but a local client call should not take more than 5s.
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
	defer cancel()
	st, err := h.lc.StatusWithoutPeers(ctx)
	if err != nil {
		http.Error(w, fmt.Sprintf("unable to check status of the tailscale device: %v", err), http.StatusServiceUnavailable)
		return
	}
	online := isOnline(st)
	addrs := getAddrs(st)
	if st.BackendState == "Running" && online && len(addrs) != 0 {
		w.Write([]byte("ok"))
	} else {
		log.Printf("healthz: tailscale device is not ready, state: %q, online: %t, addrs: %v", st.BackendState, online, addrs)
		http.Error(w, "tailscale device is not ready", http.StatusServiceUnavailable)
	}
}

// runHealthz runs a simple HTTP health endpoint on /healthz, listening on the
// provided address.
func (h *healthz) run(addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("error listening on the provided health endpoint address %q: %v", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", h)
	log.Printf("Running healthcheck endpoint at %s/healthz", addr)
	hs := &http.Server{Handler: mux}

	go func() {
		if err := hs.Serve(lis); err != nil {
			log.Fatalf("failed running health endpoint: %v", err)
		}
	}()
}

func isOnline(st *ipnstate.Status) bool {
	return st != nil && st.Self != nil && st.Self.Online
}

func getAddrs(st *ipnstate.Status) (addrs []string) {
	if st == nil || st.Self == nil {
		return
	}
	return st.Self.Addrs
}
