// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import "tailscale.com/wgengine/router"

func init() {
	router.HookNewUserspaceRouter.Set(func(opts router.NewOpts) (router.Router, error) {
		return newUserspaceBSDRouter(opts.Logf, opts.Tun, opts.NetMon, opts.Health)
	})
}
