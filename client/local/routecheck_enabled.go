// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_routecheck

package local

import (
	"context"
	"fmt"

	"tailscale.com/net/routecheck"
)

// RouteCheckProbe performs a routecheck probe and waits for its report.
func (lc *Client) RouteCheckProbe(ctx context.Context) (*routecheck.Report, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/routecheck?probe=true", 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*routecheck.Report](body)
}

// RouteCheck requests the report compiled by the latest routecheck probe.
func (lc *Client) RouteCheck(ctx context.Context, force bool) (*routecheck.Report, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/routecheck", 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*routecheck.Report](body)
}
