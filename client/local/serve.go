// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package local

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"tailscale.com/ipn"
)

// GetServeConfig return the current serve config.
//
// If the serve config is empty, it returns (nil, nil).
func (lc *Client) GetServeConfig(ctx context.Context) (*ipn.ServeConfig, error) {
	body, h, err := lc.sendWithHeaders(ctx, "GET", "/localapi/v0/serve-config", 200, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("getting serve config: %w", err)
	}
	sc, err := getServeConfigFromJSON(body)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	sc.ETag = h.Get("Etag")
	return sc, nil
}

func getServeConfigFromJSON(body []byte) (sc *ipn.ServeConfig, err error) {
	if err := json.Unmarshal(body, &sc); err != nil {
		return nil, err
	}
	return sc, nil
}

// SetServeConfig sets or replaces the serving settings.
// If config is nil, settings are cleared and serving is disabled.
func (lc *Client) SetServeConfig(ctx context.Context, config *ipn.ServeConfig) error {
	h := make(http.Header)
	if config != nil {
		h.Set("If-Match", config.ETag)
	}
	_, _, err := lc.sendWithHeaders(ctx, "POST", "/localapi/v0/serve-config", 200, jsonBody(config), h)
	if err != nil {
		return fmt.Errorf("sending serve config: %w", err)
	}
	return nil
}
