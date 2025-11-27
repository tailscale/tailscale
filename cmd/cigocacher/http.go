// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
)

type gocachedClient struct {
	baseURL     string       // base URL of the cacher server, like "http://localhost:31364".
	cl          *http.Client // http.Client to use.
	accessToken string       // Bearer token to use in the Authorization header.
	verbose     bool
}

// drainAndClose reads and throws away a small bounded amount of data. This is a
// best-effort attempt to allow connection reuse; Go's HTTP/1 Transport won't
// reuse a TCP connection unless you fully consume HTTP responses.
func drainAndClose(body io.ReadCloser) {
	io.CopyN(io.Discard, body, 4<<10)
	body.Close()
}

func tryReadErrorMessage(res *http.Response) []byte {
	msg, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
	return msg
}

func (c *gocachedClient) get(ctx context.Context, actionID string) (outputID string, resp *http.Response, err error) {
	// TODO(tomhjp): make sure we timeout if cigocached disappears, but for some
	// reason, this seemed to tank network performance.
	// // Set a generous upper limit on the time we'll wait for a response. We'll
	// // shorten this deadline later once we know the content length.
	// ctx, cancel := context.WithTimeout(ctx, time.Minute)
	// defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", c.baseURL+"/action/"+actionID, nil)
	req.Header.Set("Want-Object", "1") // opt in to single roundtrip protocol
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}

	res, err := c.cl.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		if resp == nil {
			drainAndClose(res.Body)
		}
	}()
	if res.StatusCode == http.StatusNotFound {
		return "", nil, nil
	}
	if res.StatusCode != http.StatusOK {
		msg := tryReadErrorMessage(res)
		if c.verbose {
			log.Printf("error GET /action/%s: %v, %s", actionID, res.Status, msg)
		}
		return "", nil, fmt.Errorf("unexpected GET /action/%s status %v", actionID, res.Status)
	}

	outputID = res.Header.Get("Go-Output-Id")
	if outputID == "" {
		return "", nil, fmt.Errorf("missing Go-Output-Id header in response")
	}
	if res.ContentLength == -1 {
		return "", nil, fmt.Errorf("no Content-Length from server")
	}
	return outputID, res, nil
}

func (c *gocachedClient) put(ctx context.Context, actionID, outputID string, size int64, body io.Reader) error {
	req, _ := http.NewRequestWithContext(ctx, "PUT", c.baseURL+"/"+actionID+"/"+outputID, body)
	req.ContentLength = size
	if c.accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
	}
	res, err := c.cl.Do(req)
	if err != nil {
		if c.verbose {
			log.Printf("error PUT /%s/%s: %v", actionID, outputID, err)
		}
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		msg := tryReadErrorMessage(res)
		if c.verbose {
			log.Printf("error PUT /%s/%s: %v, %s", actionID, outputID, res.Status, msg)
		}
		return fmt.Errorf("unexpected PUT /%s/%s status %v", actionID, outputID, res.Status)
	}

	return nil
}

func (c *gocachedClient) fetchStats() (string, error) {
	req, _ := http.NewRequest("GET", c.baseURL+"/session/stats", nil)
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	resp, err := c.cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
