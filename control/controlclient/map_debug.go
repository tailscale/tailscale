// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package controlclient

import "tailscale.com/metrics"

var patchifyMissStats = metrics.NewLabelMap("counter_patchify_miss", "why")

func init() {
	patchifyMissOnFalse = func(field string) {
		patchifyMissStats.Add(field, 1)
	}
}
