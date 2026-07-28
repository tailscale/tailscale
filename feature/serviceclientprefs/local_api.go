// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package serviceclientprefs

import (
	"encoding/json"
	"errors"
	"net/http"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/feature/serviceclientprefs/serviceclient"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/util/httpm"
)

func init() {
	localapi.Register("prefs/service-clients", serveServiceClientPrefs)
}

// serveServiceClientPrefs handles GET and POST /localapi/v0/prefs/service-clients. GET returns all
// of the current profile's service client prefs. POST merges one [apitype.ServiceClientPrefRequest]
// into the saved service client prefs and returns the full updated set.
func serveServiceClientPrefs(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "service-clients access denied", http.StatusForbidden)
		return
	}
	ext, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		http.Error(w, "misconfigured serviceclientprefs extension", http.StatusInternalServerError)
		return
	}
	var out serviceclient.Prefs
	switch r.Method {
	case httpm.GET:
		var err error
		if out, err = ext.serviceClientPrefs(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case httpm.POST:
		if !h.PermitWrite {
			http.Error(w, "service-clients write access denied", http.StatusForbidden)
			return
		}
		var req apitype.ServiceClientPrefRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var err error
		if out, err = ext.setServiceClientPref(req); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, errInvalidServiceClientPref) {
				status = http.StatusBadRequest
			}
			http.Error(w, err.Error(), status)
			return
		}
	default:
		http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
