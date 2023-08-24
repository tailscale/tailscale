// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package web

import (
	"net/http"
	"strings"

	"github.com/gorilla/csrf"
	"tailscale.com/util/httpm"
)

type api struct {
	s *Server
}

// ServeHTTP serves requests for the web client api.
// It should only be called by Server.ServeHTTP, via Server.apiHandler,
// which protects the handler using gorilla csrf.
func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-CSRF-Token", csrf.Token(r))
	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch path {
	case "/data":
		switch r.Method {
		case httpm.GET:
			a.s.serveGetNodeDataJSON(w, r)
		case httpm.POST:
			a.s.servePostNodeUpdate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	http.Error(w, "invalid endpoint", http.StatusNotFound)
}
