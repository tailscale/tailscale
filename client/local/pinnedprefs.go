// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_pinnedprefs

package local

import (
	"context"
	"net/http"

	"tailscale.com/ipn"
)

// GetPinnedPrefs returns the current profile's locally-pinned favorites.
//
// API maturity: this method is not considered a stable API and is subject to change between releases.
func (lc *Client) GetPinnedPrefs(ctx context.Context) (ipn.PinnedPrefs, error) {
	body, err := lc.get200(ctx, "/localapi/v0/prefs/pinned")
	if err != nil {
		return ipn.PinnedPrefs{}, err
	}
	return decodeJSON[ipn.PinnedPrefs](body)
}

// SetPinnedPrefs replaces the categories named in req for the current profile and returns the full
// updated pinned favorites.
//
// API maturity: this method is not considered a stable API and is subject to change between releases.
func (lc *Client) SetPinnedPrefs(ctx context.Context, req ipn.PinnedPrefsRequest) (ipn.PinnedPrefs, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/prefs/pinned", http.StatusOK, jsonBody(req))
	if err != nil {
		return ipn.PinnedPrefs{}, err
	}
	return decodeJSON[ipn.PinnedPrefs](body)
}
