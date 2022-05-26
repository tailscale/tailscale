// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ios || android || js
// +build ios android js

package localapi

import (
	"net/http"
	"runtime"
)

func (h *Handler) serveCert(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "disabled on "+runtime.GOOS, http.StatusNotFound)
}
