// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !wasm

package ipnlocal

import (
	"net/http"
	"runtime"
	"runtime/pprof"
	"strconv"
)

func init() {
	c2nLogHeap = func(w http.ResponseWriter, r *http.Request) {
		// Support same optional gc parameter as net/http/pprof:
		if gc, _ := strconv.Atoi(r.FormValue("gc")); gc > 0 {
			runtime.GC()
		}
		pprof.WriteHeapProfile(w)
	}
}
