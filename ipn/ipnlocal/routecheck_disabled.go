// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_routecheck

package ipnlocal

import "tailscale.com/tailcfg"

func isRouteCheckEnabled(self tailcfg.NodeView) bool {
	return false
}
