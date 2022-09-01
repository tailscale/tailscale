// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.19
// +build go1.19

package tailscale

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// TailnetDeleteRequest handles sending a DELETE request for a tailnet to control.
func (c *Client) TailnetDeleteRequest(ctx context.Context, tailnetID string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.DeleteTailnet: %w", err)
		}
	}()

	path := fmt.Sprintf("%s/api/v2/tailnet/%s", c.baseURL(), url.PathEscape(string(tailnetID)))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	c.setAuth(req)
	b, resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return handleErrorResponse(b, resp)
	}

	return nil
}
