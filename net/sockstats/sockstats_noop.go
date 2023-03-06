// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tailscale_go || !(darwin || ios || android)

package sockstats

import (
	"context"
)

func withSockStats(ctx context.Context, label Label) context.Context {
	return ctx
}

func get() *SockStats {
	return nil
}

func setLinkMonitor(lm LinkMonitor) {
}
