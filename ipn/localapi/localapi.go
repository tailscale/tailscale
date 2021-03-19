// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package localapi contains the HTTP server handlers for tailscaled's API server.
package localapi

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"

	"inet.af/netaddr"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
)

func NewHandler(b *ipnlocal.LocalBackend) *Handler {
	return &Handler{b: b}
}

type Handler struct {
	// RequiredPassword, if non-empty, forces all HTTP
	// requests to have HTTP basic auth with this password.
	// It's used by the sandboxed macOS sameuserproof GUI auth mechanism.
	RequiredPassword string

	// PermitRead is whether read-only HTTP handlers are allowed.
	PermitRead bool

	// PermitWrite is whether mutating HTTP handlers are allowed.
	PermitWrite bool

	b *ipnlocal.LocalBackend
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.b == nil {
		http.Error(w, "server has no local backend", http.StatusInternalServerError)
		return
	}
	if h.RequiredPassword != "" {
		_, pass, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		if pass != h.RequiredPassword {
			http.Error(w, "bad password", http.StatusForbidden)
			return
		}
	}
	switch r.URL.Path {
	case "/localapi/v0/whois":
		h.serveWhoIs(w, r)
	case "/localapi/v0/goroutines":
		h.serveGoroutines(w, r)
	case "/localapi/v0/status":
		h.serveStatus(w, r)
	default:
		io.WriteString(w, "tailscaled\n")
	}
}

func (h *Handler) serveWhoIs(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "whois access denied", http.StatusForbidden)
		return
	}
	b := h.b
	var ipp netaddr.IPPort
	if v := r.FormValue("addr"); v != "" {
		var err error
		ipp, err = netaddr.ParseIPPort(v)
		if err != nil {
			http.Error(w, "invalid 'addr' parameter", 400)
			return
		}
	} else {
		http.Error(w, "missing 'addr' parameter", 400)
		return
	}
	n, u, ok := b.WhoIs(ipp)
	if !ok {
		http.Error(w, "no match for IP:port", 404)
		return
	}
	res := &tailcfg.WhoIsResponse{
		Node:        n,
		UserProfile: &u,
	}
	j, err := json.MarshalIndent(res, "", "\t")
	if err != nil {
		http.Error(w, "JSON encoding error", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(j)
}

func (h *Handler) serveGoroutines(w http.ResponseWriter, r *http.Request) {
	// Require write access out of paranoia that the goroutine dump
	// (at least its arguments) might contain something sensitive.
	if !h.PermitWrite {
		http.Error(w, "goroutine dump access denied", http.StatusForbidden)
		return
	}
	buf := make([]byte, 2<<20)
	buf = buf[:runtime.Stack(buf, true)]
	w.Header().Set("Content-Type", "text/plain")
	w.Write(buf)
}

func (h *Handler) serveStatus(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "status access denied", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	e := json.NewEncoder(w)
	e.SetIndent("", "\t")
	e.Encode(h.b.Status())
}
