// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package prober

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

const maxHTTPBody = 4 << 20 // MiB

// HTTP returns a Probe that healthchecks an HTTP URL.
//
// The ProbeFunc sends a GET request for url, expects an HTTP 200
// response, and verifies that want is present in the response
// body.
func HTTP(url, wantText string) ProbeFunc {
	return func(ctx context.Context) error {
		return probeHTTP(ctx, url, []byte(wantText))
	}
}

func probeHTTP(ctx context.Context, url string, want []byte) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("constructing request: %w", err)
	}

	// Get a completely new transport each time, so we don't reuse a
	// past connection.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	defer tr.CloseIdleConnections()
	c := &http.Client{
		Transport: tr,
	}

	resp, err := c.Do(req)
	if err != nil {
		return fmt.Errorf("fetching %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("fetching %q: status code %d, want 200", url, resp.StatusCode)
	}

	bs, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	if err != nil {
		return fmt.Errorf("reading body of %q: %w", url, err)
	}

	if !bytes.Contains(bs, want) {
		return fmt.Errorf("body of %q does not contain %q", url, want)
	}

	return nil
}
