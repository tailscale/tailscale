// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

const maxHTTPBody = 4 << 20 // MiB

// HTTP returns a ProbeClass that healthchecks an HTTP URL.
//
// The probe function sends a GET request for url, expects an HTTP 200
// response, and verifies that want is present in the response
// body.
func HTTP(url, wantText string) ProbeClass {
	return ProbeClass{
		Probe: func(ctx context.Context) error {
			return probeHTTP(ctx, url, []byte(wantText))
		},
		Class: "http",
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
		// Log response body, but truncate it if it's too large; the limit
		// has been chosen arbitrarily.
		if maxlen := 300; len(bs) > maxlen {
			bs = bs[:maxlen]
		}
		return fmt.Errorf("body of %q does not contain %q (got: %q)", url, want, string(bs))
	}

	return nil
}
