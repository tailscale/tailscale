// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"fmt"
	"io"
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

	for key, val := range resp.Header {
		for _, v := range val {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
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

// metricsHandlers registers a simple HTTP metrics handler at /metrics, forwarding
// requests to tailscaled's /localapi/v0/usermetrics API.
//
// In 1.78.x and 1.80.x, it also proxies debug paths to tailscaled's debug
// endpoint if configured to ease migration for a breaking change serving user
// metrics instead of debug metrics on the "metrics" port.
func metricsHandlers(mux *http.ServeMux, lc *tailscale.LocalClient, debugAddrPort string) {
	m := &metrics{
		lc:            lc,
		debugEndpoint: debugAddrPort,
	}

	mux.HandleFunc("GET /metrics", m.handleMetrics)
	mux.HandleFunc("/debug/", m.handleDebug) // TODO(tomhjp): Remove for 1.82.0 release.
}
