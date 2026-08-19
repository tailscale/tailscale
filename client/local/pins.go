// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_favorites

package local

import (
	"context"
	"net/http"

	"tailscale.com/feature/favorites/pintype"
)

// GetPins returns the current profile's locally-pinned favorites.
//
// Pins are not currently announced over the IPN notification bus, including when they change
// because the backend switched to a different profile. The client is responsible for re-fetching
// pins on IPN state changes (e.g. profile switches) rather than assuming a previously fetched
// [pintype.Set] still applies.
//
// API maturity: this method is not considered a stable API and is subject to change between releases.
func (lc *Client) GetPins(ctx context.Context) (pintype.Set, error) {
	body, err := lc.get200(ctx, "/localapi/v0/pins")
	if err != nil {
		return pintype.Set{}, err
	}
	return decodeJSON[pintype.Set](body)
}

// SetPins replaces the categories named in req for the current profile and returns the full updated
// pinned favorites.
//
// API maturity: this method is not considered a stable API and is subject to change between releases.
func (lc *Client) SetPins(ctx context.Context, req pintype.SetRequest) (pintype.Set, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/pins", http.StatusOK, jsonBody(req))
	if err != nil {
		return pintype.Set{}, err
	}
	return decodeJSON[pintype.Set](body)
}
