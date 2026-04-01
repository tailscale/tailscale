// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_routecheck

package local

import (
	"context"

	"tailscale.com/feature"
)

// RouteCheck performs a routecheck probe to the provided IPs and waits for its report.
func (lc *Client) RouteCheck(ctx context.Context, force bool) (any, error) {
	return nil, feature.ErrUnavailable
}
