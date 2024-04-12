// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package osdiag

func supportInfo(LogSupportInfoReason) map[string]any {
	return nil
}
