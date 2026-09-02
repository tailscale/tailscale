// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_captiveportal

package local

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"tailscale.com/client/tailscale/apitype"
)

// CaptivePortalAllowLAN temporarily takes the local network back out of the
// tunnel so that a captive portal's login page hosted there can be reached
// while an exit node holds the default route. It returns when the exception
// expires at the latest; logging in to the portal ends it sooner.
//
// This is not a general exemption - it only succeeds while a captive portal
// login page is actually being reported // as blocked by an exit node. It is
// refused outright if an administrator has disallowed local network access by
// policy. The default route is not affected. this opens up the local network and nothing else.
//
// A zero duration requests the maximum the backend is willing to grant, which
// is also the ceiling any longer duration is clamped to.
//
// API maturity: this method is not considered a stable API and is subject to
// change between releases.
func (lc *Client) CaptivePortalAllowLAN(ctx context.Context, d time.Duration) (*apitype.CaptivePortalAllowLANResponse, error) {
	path := "/localapi/v0/captive-portal-allow-lan"
	request := &apitype.CaptivePortalAllowLANRequest{
		Duration: d.String(),
	}
	r, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}
	body, err := lc.send(ctx, "POST", path, http.StatusOK, bytes.NewReader(r))
	if err != nil {
		return nil, fmt.Errorf("error %w: %s", err, body)
	}
	return decodeJSON[*apitype.CaptivePortalAllowLANResponse](body)
}

// CaptivePortalRevokeLAN gives back a local network exception granted by
// [Client.CaptivePortalAllowLAN] before it expires on its own. It is not an
// error to call when no exception is active.
//
// API maturity: this method is not considered a stable API and is subject to
// change between releases.
func (lc *Client) CaptivePortalRevokeLAN(ctx context.Context) error {
	body, err := lc.send(ctx, "DELETE", "/localapi/v0/captive-portal-allow-lan", http.StatusNoContent, nil)
	if err != nil {
		return fmt.Errorf("error %w: %s", err, body)
	}
	return nil
}
