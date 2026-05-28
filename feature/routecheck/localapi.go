// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"tailscale.com/ipn/localapi"
	"tailscale.com/net/routecheck"
	"tailscale.com/util/httpm"
)

func init() {
	localapi.Register("routecheck", serveRouteCheck)
}

// ServeRouteCheck handles the API endpoint that serves the routecheck Report.
// If the probe form field is true, then this handler will refresh the Report
// before serving it.
// If the timeout form field is a valid duration, the probe will consider a node
// to be unreachable if it doesn’t respond before the timeout expires.
func serveRouteCheck(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	rc := ClientFor(h.LocalBackend())
	if rc == nil {
		http.Error(w, "routecheck is not enabled", http.StatusServiceUnavailable)
		return
	}

	if r.Method != httpm.POST {
		http.Error(w, "want POST", http.StatusMethodNotAllowed)
		return
	}

	var err error
	var report *routecheck.Report
	if defBool(r.FormValue("probe"), false) {
		timeout := defDuration(r.FormValue("timeout"), routecheck.DefaultTimeout)
		timeout = min(max(0, timeout), 60*time.Second) // clamp to [0s, 60s]
		report, err = rc.Refresh(r.Context(), timeout)
	} else {
		report = rc.Report()
	}
	if err != nil {
		localapi.WriteErrorJSON(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if report == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	json.NewEncoder(w).Encode(report)
}

func defBool(a string, def bool) bool {
	if a == "" {
		return def
	}
	v, err := strconv.ParseBool(a)
	if err != nil {
		return def
	}
	return v
}

func defDuration(a string, def time.Duration) time.Duration {
	if a == "" {
		return def
	}
	v, err := time.ParseDuration(a)
	if err != nil {
		return def
	}
	return v
}
