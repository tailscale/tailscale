// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

//lint:file-ignore ST1000 see filesharingstatus_windows.go

package osshare

import (
	"tailscale.com/types/logger"
)

func SetFileSharingEnabled(enabled bool, logf logger.Logf) {}
