// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_clientproxy

package main

import (
	"context"

	"tailscale.com/envknob"
	"tailscale.com/feature/clientproxy"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/types/logger"
)

// defaultClientProxyPort is the loopback port the browser client proxy listens
// on when TS_CLIENT_PROXY_PORT is unset. It matches the default the
// client-portal probes.
const defaultClientProxyPort = 4280

func init() {
	hookStartClientProxy.Set(func(ctx context.Context, logf logger.Logf, lb *ipnlocal.LocalBackend) {
		// Off by default; opt in with TS_CLIENT_PROXY=1.
		if !envknob.Bool("TS_CLIENT_PROXY") {
			return
		}
		port := defaultClientProxyPort
		if p, ok := envknob.LookupInt("TS_CLIENT_PROXY_PORT"); ok {
			port = p
		}
		if err := clientproxy.Start(ctx, logf, lb, port); err != nil {
			logf("clientproxy: failed to start: %v", err)
		}
	})
}
