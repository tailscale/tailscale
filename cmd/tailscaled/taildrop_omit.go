// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_taildrop

package main

import (
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/types/logger"
)

func configureTaildrop(logf logger.Logf, lb *ipnlocal.LocalBackend) {
	// Nothing.
}
