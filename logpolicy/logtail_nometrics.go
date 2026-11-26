// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_logtail || ts_omit_clientmetrics

package logpolicy

import "tailscale.com/logtail"

func exportClientMetrics(logger *logtail.Logger) {}
