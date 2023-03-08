// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tailscale_go || !(darwin || ios || android)

package sockstats

import (
	"context"
)

const IsAvailable = false

func withSockStats(ctx context.Context, label Label) context.Context {
	return ctx
}

func get() *SockStats {
	return nil
}

func getValidation() *ValidationSockStats {
	return nil
}

func setLinkMonitor(lm LinkMonitor) {
}
