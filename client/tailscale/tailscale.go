// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

// Package tailscale contains Go clients for the Tailscale Local API and
// Tailscale control plane API.
//
// Warning: this package is in development and makes no API compatibility
// promises as of 2022-04-29. It is subject to change at any time.
package tailscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

// I_Acknowledge_This_API_Is_Unstable must be set true to use this package
// for now. It was added 2022-04-29 when it was moved to this git repo
// and will be removed when the public API has settled.
//
// TODO(bradfitz): remove this after the we're happy with the public API.
var I_Acknowledge_This_API_Is_Unstable = false

// TODO: use url.PathEscape() for deviceID and tailnets when constructing requests.

// DefaultURL is the default base URL used for API calls.
const DefaultURL = "https://api.tailscale.com"

// maxSize is the maximum read size (10MB) of responses from the server.
const maxReadSize int64 = 10 * 1024 * 1024

// Client is needed to make different API calls to the Tailscale server.
// It holds all the necessary information so that it can be reused to make
// multiple requests for the same user.
// Unless overridden, "api.tailscale.com" is the default BaseURL.
type Client struct {
	// Tailnet is the globally unique identifier for a Tailscale network, such
	// as "example.com" or "user@gmail.com".
	Tailnet    string
	APIKey     string
	BaseURL    string
	HTTPClient *http.Client
}

// New is a convenience method for instantiating a new Client.
//
// tailnet is the globally unique identifier for a Tailscale network, such
// as "example.com" or "user@gmail.com".
// If httpClient is nil, then http.DefaultClient is used.
// "api.tailscale.com" is set as the BaseURL for the returned client
// and can be changed manually by the user.
func New(tailnet string, key string, httpClient *http.Client) *Client {
	c := &Client{
		Tailnet:    tailnet,
		APIKey:     key,
		BaseURL:    DefaultURL,
		HTTPClient: httpClient,
	}

	if httpClient == nil {
		c.HTTPClient = http.DefaultClient
	}

	return c
}

// sendRequest add the authenication key to the request and sends it. It
// receives the response and reads up to 10MB of it.
func (c *Client) sendRequest(req *http.Request) ([]byte, *http.Response, error) {
	if !I_Acknowledge_This_API_Is_Unstable {
		return nil, nil, errors.New("use of Client without setting I_Acknowledge_This_API_Is_Unstable")
	}
	req.SetBasicAuth(c.APIKey, "")
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, resp, err
	}
	defer resp.Body.Close()

	// Read response. Limit the response to 10MB.
	body := io.LimitReader(resp.Body, maxReadSize)
	b, err := ioutil.ReadAll(body)
	return b, resp, err
}

// ErrResponse is the HTTP error returned by the Tailscale server.
type ErrResponse struct {
	Status  int
	Message string
}

func (e ErrResponse) Error() string {
	return fmt.Sprintf("Status: %d, Message: %q", e.Status, e.Message)
}

// handleErrorResponse decodes the error message from the server and returns
// an ErrResponse from it.
func handleErrorResponse(b []byte, resp *http.Response) error {
	var errResp ErrResponse
	if err := json.Unmarshal(b, &errResp); err != nil {
		return err
	}
	errResp.Status = resp.StatusCode
	return errResp
}
