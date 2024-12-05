// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || android || js

package localapi

import (
	"net/http"
	"runtime"
)

func (h *Handler) serveCert(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "disabled on "+runtime.GOOS, http.StatusNotFound)
}
