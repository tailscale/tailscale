// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_sync

package main

import (
	"tailscale.com/tailsync/tailsyncimpl"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
)

func init() {
	hookSetSysSync.Set(func(sys *tsd.System, logf logger.Logf) {
		sys.Set(tailsyncimpl.NewService(logf))
	})
}
