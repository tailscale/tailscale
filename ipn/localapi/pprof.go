// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !android && !js

// We don't include it on mobile where we're more memory constrained and
// there's no CLI to get at the results anyway.

package localapi

import (
	"net/http"
	"net/http/pprof"
)

func init() {
	servePprofFunc = servePprof
}

func servePprof(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	switch name {
	case "profile":
		pprof.Profile(w, r)
	default:
		pprof.Handler(name).ServeHTTP(w, r)
	}
}
