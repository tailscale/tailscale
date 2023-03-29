// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(linux || darwin || freebsd || openbsd)

package permissions

import (
	"runtime"

	"tailscale.com/types/logger"
)

func permissionsImpl(logf logger.Logf) error {
	logf("unsupported on %s/%s", runtime.GOOS, runtime.GOARCH)
	return nil
}
