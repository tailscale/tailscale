// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package favorites

import (
	"encoding/json"
	"net/http"

	"tailscale.com/feature/favorites/pintype"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/util/httpm"
)

func init() {
	localapi.Register("pins", servePins)
}

// servePins handles GET and POST /localapi/v0/pins for the current profile: GET returns the pinned
// favorites, POST applies a [pintype.SetRequest] and returns the updated set.
func servePins(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "pins access denied", http.StatusForbidden)
		return
	}
	ext, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		http.Error(w, "misconfigured favorites extension", http.StatusInternalServerError)
		return
	}
	var out pintype.Set
	switch r.Method {
	case httpm.GET:
		var err error
		if out, err = ext.currentPins(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case httpm.POST:
		if !h.PermitWrite {
			http.Error(w, "pins write access denied", http.StatusForbidden)
			return
		}
		var req pintype.SetRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var err error
		if out, err = ext.setPins(req); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	default:
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
