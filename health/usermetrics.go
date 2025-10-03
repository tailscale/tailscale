// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_health && !ts_omit_usermetrics

package health

import (
	"expvar"

	"tailscale.com/feature/buildfeatures"
	"tailscale.com/util/usermetric"
)

const MetricLabelWarning = "warning"

type metricHealthMessageLabel struct {
	// TODO: break down by warnable.severity as well?
	Type string
}

// SetMetricsRegistry sets up the metrics for the Tracker. It takes
// a usermetric.Registry and registers the metrics there.
func (t *Tracker) SetMetricsRegistry(reg *usermetric.Registry) {
	if !buildfeatures.HasHealth {
		return
	}

	if reg == nil || t.metricHealthMessage != nil {
		return
	}

	m := usermetric.NewMultiLabelMapWithRegistry[metricHealthMessageLabel](
		reg,
		"tailscaled_health_messages",
		"gauge",
		"Number of health messages broken down by type.",
	)

	m.Set(metricHealthMessageLabel{
		Type: MetricLabelWarning,
	}, expvar.Func(func() any {
		if t.nil() {
			return 0
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		t.updateBuiltinWarnablesLocked()
		return int64(len(t.stringsLocked()))
	}))
	t.metricHealthMessage = m
}
