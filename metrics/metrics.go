// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package metrics contains expvar & Prometheus types and code used by
// Tailscale for monitoring.
package metrics

import "expvar"

// Set is a string-to-Var map variable that satisfies the expvar.Var
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

// LabelMap is a string-to-Var map variable that satisfies the
// expvar.Var interface.
//
// Semantically, this is mapped by tsweb's Prometheus exporter as a
// collection of variables with the same name, with a varying label
// value. Use this to export things that are intuitively breakdowns
// into different buckets.
type LabelMap struct {
	Label string
	expvar.Map
}

// Get returns a direct pointer to the expvar.Int for key, creating it
// if necessary.
func (m *LabelMap) Get(key string) *expvar.Int {
	m.Add(key, 0)
	return m.Map.Get(key).(*expvar.Int)
}

// GetFloat returns a direct pointer to the expvar.Float for key, creating it
// if necessary.
func (m *LabelMap) GetFloat(key string) *expvar.Float {
	m.AddFloat(key, 0.0)
	return m.Map.Get(key).(*expvar.Float)
}

// CurrentFDs reports how many file descriptors are currently open.
//
// It only works on Linux. It returns zero otherwise.
func CurrentFDs() int {
	return currentFDs()
}
