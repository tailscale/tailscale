// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appconnectors

import (
	"encoding/json"
	"errors"
	"net/http"

	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/types/appctype"
	"tailscale.com/util/httpm"
)

func init() {
	localapi.Register("appc-route-info", serveGetAppcRouteInfo)
}

func serveGetAppcRouteInfo(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	ext, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}
	ri, err := ext.readRouteInfo()
	if err != nil {
		if errors.Is(err, ipn.ErrStateNotExist) {
			ri = &appctype.RouteInfo{}
		} else {
			localapi.WriteErrorJSON(w, err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ri)
}
