// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serviceclientprefs

package local

import (
	"context"
	"net/http"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/feature/serviceclientprefs/serviceclient"
)

// GetServiceClientPrefs returns all of the current profile's [serviceclient.Prefs].
//
// API maturity: this method is not considered a stable API and is subject to change between releases.
func (lc *Client) GetServiceClientPrefs(ctx context.Context) (serviceclient.Prefs, error) {
	body, err := lc.get200(ctx, "/localapi/v0/prefs/service-clients")
	if err != nil {
		return nil, err
	}
	return decodeJSON[serviceclient.Prefs](body)
}

// SetServiceClientPref merges the non-empty fields from an [apitype.ServiceClientPrefRequest] into the
// saved service client prefs for the current profile and returns the full updated set.
//
// API maturity: this method is not considered a stable API and is subject to change between releases.
func (lc *Client) SetServiceClientPref(ctx context.Context, req apitype.ServiceClientPrefRequest) (serviceclient.Prefs, error) {
	body, err := lc.send(ctx, "POST", "/localapi/v0/prefs/service-clients", http.StatusOK, jsonBody(req))
	if err != nil {
		return nil, err
	}
	return decodeJSON[serviceclient.Prefs](body)
}
