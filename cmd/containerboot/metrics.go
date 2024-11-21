// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"

	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
)

// metrics is a simple metrics HTTP server, if enabled it forwards requests to
// the tailscaled's LocalAPI usermetrics endpoint at /localapi/v0/usermetrics.
type metrics struct {
	debugEndpoint string
	lc            *tailscale.LocalClient
}

func proxy(w http.ResponseWriter, r *http.Request, url string, do func(*http.Request) (*http.Response, error)) {
	req, err := http.NewRequestWithContext(r.Context(), r.Method, url, r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to construct request: %s", err), http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone()

	resp, err := do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to proxy request: %s", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	w.WriteHeader(resp.StatusCode)
	for key, val := range resp.Header {
		for _, v := range val {
			w.Header().Add(key, v)
		}
	}
	if _, err := io.Copy(w, resp.Body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (m *metrics) handleMetrics(w http.ResponseWriter, r *http.Request) {
	localAPIURL := "http://" + apitype.LocalAPIHost + "/localapi/v0/usermetrics"
	proxy(w, r, localAPIURL, m.lc.DoLocalRequest)
}

func (m *metrics) handleDebug(w http.ResponseWriter, r *http.Request) {
	if m.debugEndpoint == "" {
		http.Error(w, "debug endpoint not configured", http.StatusNotFound)
		return
	}

	debugURL := "http://" + m.debugEndpoint + r.URL.Path
	proxy(w, r, debugURL, http.DefaultClient.Do)
}

// runMetrics runs a simple HTTP metrics endpoint at <addr>/metrics, forwarding
// requests to tailscaled's /localapi/v0/usermetrics API.
//
// In 1.78.x and 1.80.x, it also proxies debug paths to tailscaled's debug
// endpoint if configured to ease migration for a breaking change serving user
// metrics instead of debug metrics on the "metrics" port.
func runMetrics(addr string, m *metrics) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("error listening on the provided metrics endpoint address %q: %v", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", m.handleMetrics)
	mux.HandleFunc("/debug/", m.handleDebug) // TODO(tomhjp): Remove for 1.82.0 release.

	log.Printf("Running metrics endpoint at %s/metrics", addr)
	ms := &http.Server{Handler: mux}

	go func() {
		if err := ms.Serve(ln); err != nil {
			log.Fatalf("failed running metrics endpoint: %v", err)
		}
	}()
}
