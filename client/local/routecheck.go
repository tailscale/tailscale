// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_routecheck

package local

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"tailscale.com/net/routecheck"
)

// ErrReportPending is returned by [Client.RouteCheck] and [Client.RouteCheckProbe]
// when the report is pending.
var ErrRouteCheckReportUnavailable = errors.New("report pending")

// RouteCheckProbe performs a routecheck probe and waits for its report.
func (lc *Client) RouteCheckProbe(ctx context.Context) (*routecheck.Report, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/routecheck?probe=true", http.StatusOK, nil)
	if err != nil {
		if hs, ok := errors.AsType[httpStatusError](err); ok && hs.HTTPStatus == http.StatusNoContent {
			return nil, ErrRouteCheckReportUnavailable
		}
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*routecheck.Report](body)
}

// RouteCheck requests the report compiled by the latest routecheck probe.
func (lc *Client) RouteCheck(ctx context.Context) (*routecheck.Report, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/routecheck", http.StatusOK, nil)
	if err != nil {
		if hs, ok := errors.AsType[httpStatusError](err); ok && hs.HTTPStatus == http.StatusNoContent {
			return nil, ErrRouteCheckReportUnavailable
		}
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*routecheck.Report](body)
}
