// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !wasm && !ts_omit_debug

package ipnlocal

import (
	"fmt"
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

	c2nPprof = func(w http.ResponseWriter, r *http.Request, profile string) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		p := pprof.Lookup(string(profile))
		if p == nil {
			http.Error(w, "Unknown profile", http.StatusNotFound)
			return
		}
		gc, _ := strconv.Atoi(r.FormValue("gc"))
		if profile == "heap" && gc > 0 {
			runtime.GC()
		}
		debug, _ := strconv.Atoi(r.FormValue("debug"))
		if debug != 0 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, profile))
		}
		p.WriteTo(w, debug)
	}
}
