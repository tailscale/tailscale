// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"tailscale.com/ipn/ipnstate"
	healthz "tailscale.com/kube/health"
	"tailscale.com/types/logger"
)

// healthLocalClient is the subset of [local.Client] used by the health checks.
type healthLocalClient interface {
	StatusWithoutPeers(context.Context) (*ipnstate.Status, error)
}

// registerHealthChecks registers the /livez and /readyz probes and their
// checks on mux. It must be called before mux is served.
func registerHealthChecks(mux *http.ServeMux, lc healthLocalClient, logf logger.Logf) {
	healthz.RegisterLivezHandlers(mux, logf).AddCheck("localapi", localAPIResponding(lc))
	healthz.RegisterReadyzHandlers(mux, logf).AddCheck("netmap", hasTailnetIPs(lc))
}

// localAPIResponding returns a check that passes while the LocalAPI answers a
// cheap request.
func localAPIResponding(lc healthLocalClient) func(context.Context) error {
	return func(ctx context.Context) error {
		if _, err := lc.StatusWithoutPeers(ctx); err != nil {
			return fmt.Errorf("failed to get status: %w", err)
		}
		return nil
	}
}

// hasTailnetIPs returns a check that passes once the node has received a
// netmap with its tailnet IPs.
func hasTailnetIPs(lc healthLocalClient) func(context.Context) error {
	return func(ctx context.Context) error {
		st, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("failed to get status: %w", err)
		}
		if st.Self == nil || len(st.Self.TailscaleIPs) == 0 {
			return errors.New("no netmap with tailnet IPs received yet")
		}
		return nil
	}
}
