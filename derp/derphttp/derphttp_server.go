// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package derphttp

import (
	"log"
	"net/http"

	"tailscale.com/derp"
)

func Handler(s *derp.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.Header.Get("Upgrade"); p != "WebSocket" && p != "DERP" {
			http.Error(w, "DERP requires connection upgrade", http.StatusUpgradeRequired)
			return
		}
		w.Header().Set("Upgrade", "DERP")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)

		h, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "HTTP does not support general TCP support", 500)
			return
		}
		netConn, conn, err := h.Hijack()
		if err != nil {
			log.Printf("Hijack failed: %v", err)
			http.Error(w, "HTTP does not support general TCP support", 500)
			return
		}
		s.Accept(netConn, conn, netConn.RemoteAddr().String())
	})
}
