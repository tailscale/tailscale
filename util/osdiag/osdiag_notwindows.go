// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package osdiag

import "tailscale.com/types/logger"

func logSupportInfo(logger.Logf, LogSupportInfoReason) {
}
