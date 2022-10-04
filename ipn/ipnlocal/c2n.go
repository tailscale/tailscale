// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/goroutines"
)

func (b *LocalBackend) handleC2N(w http.ResponseWriter, r *http.Request) {
	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	switch r.URL.Path {
	case "/echo":
		// Test handler.
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	case "/debug/goroutines":
		w.Header().Set("Content-Type", "text/plain")
		w.Write(goroutines.ScrubbedGoroutineDump())
	case "/debug/prefs":
		writeJSON(b.Prefs())
	case "/debug/metrics":
		w.Header().Set("Content-Type", "text/plain")
		clientmetric.WritePrometheusExpositionFormat(w)
	case "/debug/component-logging":
		component := r.FormValue("component")
		secs, _ := strconv.Atoi(r.FormValue("secs"))
		if secs == 0 {
			secs -= 1
		}
		until := time.Now().Add(time.Duration(secs) * time.Second)
		err := b.SetComponentDebugLogging(component, until)
		var res struct {
			Error string `json:",omitempty"`
		}
		if err != nil {
			res.Error = err.Error()
		}
		writeJSON(res)
	case "/ssh/usernames":
		var req tailcfg.C2NSSHUsernamesRequest
		if r.Method == "POST" {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		res, err := b.getSSHUsernames(&req)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(res)
	default:
		http.Error(w, "unknown c2n path", http.StatusBadRequest)
	}
}
