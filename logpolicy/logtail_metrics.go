// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_logtail && !ts_omit_clientmetrics

package logpolicy

import (
	"expvar"

	"tailscale.com/logtail"
	"tailscale.com/util/clientmetric"
)

func exportClientMetrics(logger *logtail.Logger) {
	if m, _ := logger.ExpVar().(interface{ Get(string) expvar.Var }); m != nil {
		if m2, _ := m.Get("buffer").(interface{ Get(string) expvar.Var }); m2 != nil {
			if v, _ := m2.Get("counter_filched_bytes").(*expvar.Int); v != nil {
				clientmetric.NewCounterFunc("logtail_filched_bytes", v.Value)
			}
			if v, _ := m2.Get("counter_dropped_bytes").(*expvar.Int); v != nil {
				clientmetric.NewCounterFunc("logtail_dropped_bytes", v.Value)
			}
			if v, _ := m2.Get("gauge_stored_bytes").(*expvar.Int); v != nil {
				clientmetric.NewGaugeFunc("logtail_stored_bytes", v.Value)
			}
		}
	}
}
