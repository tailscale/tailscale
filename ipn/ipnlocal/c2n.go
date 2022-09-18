// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"encoding/json"
	"io"
	"net/http"

	"tailscale.com/tailcfg"
)

func (b *LocalBackend) handleC2N(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/echo":
		// Test handler.
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	default:
		http.Error(w, "unknown c2n path", http.StatusBadRequest)
	}
}
