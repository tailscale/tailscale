// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || android || ts_omit_debugeventbus

package eventbus

import "tailscale.com/tsweb"

func registerHTTPDebugger(d *Debugger, td *tsweb.DebugHandler) {
	// The event bus debugging UI uses html/template, which uses
	// reflection for method lookups. This forces the compiler to
	// retain a lot more code and information to make dynamic method
	// dispatch work, which is unacceptable bloat for the iOS build.
	// We also disable it on Android while we're at it, as nobody
	// is debugging Tailscale internals on Android.
	//
	// TODO: https://github.com/tailscale/tailscale/issues/15297 to
	// bring the debug UI back to iOS somehow.
}
