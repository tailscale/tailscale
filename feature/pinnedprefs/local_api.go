// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package pinnedprefs

import (
	"encoding/json"
	"net/http"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/util/httpm"
)

func init() {
	localapi.Register("prefs/pinned", servePinnedPrefs)
}

// servePinnedPrefs handles GET and POST /localapi/v0/prefs/pinned for the current profile: GET
// returns the pinned favorites, POST applies an [ipn.PinnedPrefsRequest] and returns the updated set.
func servePinnedPrefs(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "pinned access denied", http.StatusForbidden)
		return
	}
	ext, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		http.Error(w, "misconfigured pinnedprefs extension", http.StatusInternalServerError)
		return
	}
	var out ipn.PinnedPrefs
	switch r.Method {
	case httpm.GET:
		var err error
		if out, err = ext.pinnedPrefs(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case httpm.POST:
		if !h.PermitWrite {
			http.Error(w, "pinned write access denied", http.StatusForbidden)
			return
		}
		var req ipn.PinnedPrefsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var err error
		if out, err = ext.setPinnedPrefs(req); err != nil {
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
