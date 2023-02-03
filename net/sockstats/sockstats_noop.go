// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tailscale_go || !(darwin || ios || android)

package sockstats

import (
	"context"

	"tailscale.com/wgengine/monitor"
)

func withSockStats(ctx context.Context, label string) context.Context {
	return ctx
}

func get() *SockStats {
	return nil
}

func setLinkMonitor(lm *monitor.Mon) {
}
