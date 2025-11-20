// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !wasm

package tsweb

import (
	"net/http"
	"net/http/pprof"
)

func addProfilingHandlers(d *DebugHandler) {
	// pprof.Index serves everything that runtime/pprof.Lookup finds:
	// goroutine, threadcreate, heap, allocs, block, mutex
	d.Handle("pprof/", "pprof (index)", http.HandlerFunc(pprof.Index))
	// But register the other ones from net/http/pprof directly:
	d.HandleSilent("pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
	d.HandleSilent("pprof/profile", http.HandlerFunc(pprof.Profile))
	d.HandleSilent("pprof/symbol", http.HandlerFunc(pprof.Symbol))
	d.HandleSilent("pprof/trace", http.HandlerFunc(pprof.Trace))
	d.URL("/debug/pprof/goroutine?debug=1", "Goroutines (collapsed)")
	d.URL("/debug/pprof/goroutine?debug=2", "Goroutines (full)")
}
