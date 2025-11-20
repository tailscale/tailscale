// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build js && wasm

package tsweb

func addProfilingHandlers(d *DebugHandler) {
	// No pprof in js builds, pprof doesn't work and bloats the build.
}
