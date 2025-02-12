// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package tailscale

import (
	"context"
	"fmt"
	"net/http"

	"tailscale.com/util/httpm"
)

// TailnetDeleteRequest handles sending a DELETE request for a tailnet to control.
func (c *Client) TailnetDeleteRequest(ctx context.Context, tailnetID string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.DeleteTailnet: %w", err)
		}
	}()

	path := c.BuildTailnetURL("tailnet")
	req, err := http.NewRequestWithContext(ctx, httpm.DELETE, path, nil)
	if err != nil {
		return err
	}

	c.setAuth(req)
	b, resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return HandleErrorResponse(b, resp)
	}

	return nil
}
