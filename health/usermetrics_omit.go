// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_health || ts_omit_usermetrics

package health

func (t *Tracker) SetMetricsRegistry(any) {}
