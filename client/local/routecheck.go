// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_routecheck

package local

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"tailscale.com/ipn/routecheck"
)

// RouteCheck performs a routecheck probe to the provided IPs and waits for its report.
func (lc *Client) RouteCheck(ctx context.Context, force bool) (*routecheck.Report, error) {
	v := url.Values{}
	v.Set("force", strconv.FormatBool(force))
	body, err := lc.send(ctx, "POST", "/localapi/v0/routecheck?"+v.Encode(), 200, nil)
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*routecheck.Report](body)
}
