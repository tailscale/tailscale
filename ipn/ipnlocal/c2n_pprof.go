// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !wasm

package ipnlocal

import (
	"net/http"
	"runtime/pprof"
)

func init() {
	c2nLogHeap = func(w http.ResponseWriter, r *http.Request) {
		pprof.WriteHeapProfile(w)
	}

	c2nLogAllocs = func(w http.ResponseWriter, r *http.Request) {
		pprof.Lookup("allocs").WriteTo(w, 0)
	}
}
