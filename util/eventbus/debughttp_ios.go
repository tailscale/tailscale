// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios

package eventbus

import "tailscale.com/tsweb"

func registerHTTPDebugger(d *Debugger, td *tsweb.DebugHandler) {
	// The event bus debugging UI uses html/template, which uses
	// reflection for method lookups. This forces the compiler to
	// retain a lot more code and information to make dynamic method
	// dispatch work, which is unacceptable bloat for the iOS build.
	//
	// TODO: https://github.com/tailscale/tailscale/issues/15297 to
	// bring the debug UI back to iOS somehow.
}
