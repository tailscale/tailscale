// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// package tailnetlock registers the tailnet lock debug C2N handler. In the
// future, all tailnet lock code should move here.
package tailnetlock

import (
	"fmt"
	"net/http"
	"strconv"

	"tailscale.com/cmd/tailscale/cli/jsonoutput"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn/ipnlocal"
)

func init() {
	feature.Register("tailnetlock")
	ipnlocal.RegisterC2N("/debug/tka/log", handleC2NDebugTKALog)
}

const defaultC2NLogLimit = 50
const maxC2NLogLimit = 1000

func handleC2NDebugTKALog(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDebug {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}

	logf := b.Logger()
	logf("c2n: %s %s received", r.Method, r.URL)

	limit := defaultC2NLogLimit
	limitStr := r.URL.Query().Get("limit")
	if limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil {
			limit = min(parsed, maxC2NLogLimit)
		}
	}

	updates, err := b.NetworkLockLog(limit)
	if ipnlocal.IsNetworkLockNotActive(err) {
		http.Error(w, "tailnet lock not active", http.StatusBadRequest)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprintf("failed to get tailnet lock log: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	jsonoutput.PrintNetworkLockLogJSONV1(w, updates)
}
