// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_routecheck

package localapi

import (
	"net/http"

	"tailscale.com/feature"
)

func (h *Handler) serveRouteCheck(w http.ResponseWriter, r *http.Request) {
	http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotFound)
}
