// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || android

package derpserver

import "context"

func (c *sclient) startStatsLoop(ctx context.Context) {
	// Nothing to do
	return
}
