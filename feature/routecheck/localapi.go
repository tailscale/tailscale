// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"context"
	"errors"
	"net/http"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	jsonv1 "github.com/go-json-experiment/json/v1"

	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/routecheck"
	"tailscale.com/util/def"
	"tailscale.com/util/httpm"
)

func init() {
	localapi.Register("routecheck", serveRouteCheck)
	localapi.HookRouteCheckRefresh.Set(routeCheckRefresh)
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

	report := rc.Report()
	if def.Bool(r.FormValue("probe"), false) {
		timeout := def.Duration(r.FormValue("timeout"), routecheck.DefaultTimeout)
		timeout = clampRouteCheckTimeout(timeout)
		rp, err := rc.Refresh(r.Context(), timeout)
		if err != nil {
			localapi.WriteErrorJSON(w, err)
			return
		}
		report = rp
	}

	w.Header().Set("Content-Type", "application/json")
	if report == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// TODO(sfllaw): Since ipn/localapi is still using encoding/json
	// with its default options, marshal with DefaultOptionsV1.
	jsonv2.MarshalWrite(w, report, jsonv1.DefaultOptionsV1())
}

func clampRouteCheckTimeout(timeout time.Duration) time.Duration {
	if timeout < 0 {
		timeout = routecheck.DefaultTimeout
	}
	return min(max(0, timeout), 60*time.Second) // clamp to [0s, 60s]
}

// routeCheckRefresh is a localapi hook for refreshing the [routecheck.Client.Report].
// If the timeout is 0, all probes will timeout immediately.
// If the timeout is negative, then all probes will use the [DefaultTimeout].
func routeCheckRefresh(b *ipnlocal.LocalBackend, ctx context.Context, timeout time.Duration) error {
	rc := ClientFor(b)
	if rc == nil {
		return errors.New("routecheck is not enabled")
	}
	_, err := rc.Refresh(ctx, clampRouteCheckTimeout(timeout))
	return err
}
