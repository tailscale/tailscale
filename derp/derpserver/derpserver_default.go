// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || android

package derpserver

import "context"

func (c *sclient) startStatsLoop(ctx context.Context) {
	// Nothing to do
	return
}

// recordSavedSyn is a no-op on non-Linux platforms; TCP_SAVE_SYN is
// Linux-only.
func (c *sclient) recordSavedSyn() {}
