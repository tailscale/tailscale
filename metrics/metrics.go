// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package metrics contains expvar & Prometheus types and code used by
// Tailscale for monitoring.
package metrics

import "expvar"

// Map is a string-to-Var map variable that satisfies the expvar.Var
// interface.
//
// Semantically, this is mapped by tsweb's Prometheus exporter as a
// collection of unrelated variables exported with a common prefix.
//
// This lets us have tsweb recognize *expvar.Map for different
// purposes in the future. (Or perhaps all uses of expvar.Map will
// require explicit types like this one, declaring how we want tsweb
// to export it to Prometheus.)
type Set struct {
	expvar.Map
}
