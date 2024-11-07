// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"io"
	"log"
	"net"
	"net/http"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/util/httpm"
)

// metrics is a simple metrics HTTP server, if enabled it forwards requests to
// the tailscaled's LocalAPI usermetrics endpoint at /localapi/v0/usermetrics.
type metrics struct {
	lc *tailscale.LocalClient
}

func (m *metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	localAPIURL := "http://" + apitype.LocalAPIHost + "/localapi/v0/usermetrics"
	req, err := http.NewRequestWithContext(r.Context(), httpm.GET, localAPIURL, nil)
	if err != nil {
		http.Error(w, "failed to construct request", http.StatusInternalServerError)
		return
	}

	resp, err := m.lc.DoLocalRequest(req)
	if err != nil {
		http.Error(w, err.Error(), resp.StatusCode)
		return
	}
	defer resp.Body.Close()

	// Send response back to web frontend.
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// runMetrics runs a simple HTTP metrics endpoint at <addr>/metrics, forwarding
// requests to tailscaled's /localapi/v0/usermetrics API.
func runMetrics(addr string, m *metrics) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("error listening on the provided metrics endpoint address %q: %v", addr, err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", m)
	log.Printf("Running metrics endpoint at %s/metrics", addr)
	ms := &http.Server{Handler: mux}

	go func() {
		if err := ms.Serve(ln); err != nil {
			log.Fatalf("failed running metrics endpoint: %v", err)
		}
	}()
}
