// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || android

package ethtool

import (
	"runtime"

	"tailscale.com/types/logger"
)

func ethtoolImpl(logf logger.Logf) error {
	logf("unsupported on %s/%s", runtime.GOOS, runtime.GOARCH)
	return nil
}
