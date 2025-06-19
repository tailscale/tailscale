// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_derpserver && (!linux || android)

package derp

import "context"

func (c *sclient) startStatsLoop(ctx context.Context) {
	// Nothing to do
	return
}
