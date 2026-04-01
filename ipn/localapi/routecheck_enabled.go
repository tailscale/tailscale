// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_routecheck

package localapi

import (
	"encoding/json"
	"net/http"
	"time"

	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/feature/routecheck"
	"tailscale.com/util/httpm"
)

func (h *Handler) serveRouteCheck(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasRouteCheck {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}

	rc := routecheck.ClientFor(h.b)
	if rc == nil {
		http.Error(w, "routecheck is not enabled", http.StatusServiceUnavailable)
		return
	}

	if r.Method != httpm.POST {
		http.Error(w, "want POST", http.StatusBadRequest)
		return
	}

	var err error
	var report *routecheck.Report
	if defBool(r.FormValue("force"), false) {
		timeout := defDuration(r.FormValue("timeout"), routecheck.DefaultTimeout)
		timeout = min(max(0, timeout), 60*time.Second) // clamp to [0s, 60s]
		report, err = rc.Refresh(r.Context(), timeout)
	} else {
		report = rc.Report()
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "text.plain")
		w.Write([]byte(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if report == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	json.NewEncoder(w).Encode(report)
}
