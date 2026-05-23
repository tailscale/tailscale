// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_routecheck

package local

import (
	"context"

	"tailscale.com/feature"
)

// RouteCheckProbe performs a routecheck probe and waits for its report.
func (lc *Client) RouteCheckProbe(ctx context.Context) (any, error) {
	return nil, feature.ErrUnavailable
}

// RouteCheck requests the report compiled by the latest routecheck probe.
func (lc *Client) RouteCheck(ctx context.Context, force bool) (any, error) {
	return nil, feature.ErrUnavailable
}
