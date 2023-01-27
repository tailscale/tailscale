// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

// Package tailscale contains Go clients for the Tailscale LocalAPI and
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
	"net/http"
)

// I_Acknowledge_This_API_Is_Unstable must be set true to use this package
// for now. It was added 2022-04-29 when it was moved to this git repo
// and will be removed when the public API has settled.
//
// TODO(bradfitz): remove this after the we're happy with the public API.
var I_Acknowledge_This_API_Is_Unstable = false

// TODO: use url.PathEscape() for deviceID and tailnets when constructing requests.

const defaultAPIBase = "https://api.tailscale.com"

// maxSize is the maximum read size (10MB) of responses from the server.
const maxReadSize = 10 << 20

// Client makes API calls to the Tailscale control plane API server.
//
// Use NewClient to instantiate one. Exported fields should be set before
// the client is used and not changed thereafter.
type Client struct {
	// tailnet is the globally unique identifier for a Tailscale network, such
	// as "example.com" or "user@gmail.com".
	tailnet string
	// auth is the authentication method to use for this client.
	// nil means none, which generally won't work, but won't crash.
	auth AuthMethod

	// BaseURL optionally specifies an alternate API server to use.
	// If empty, "https://api.tailscale.com" is used.
	BaseURL string

	// HTTPClient optionally specifies an alternate HTTP client to use.
	// If nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) baseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}
	return defaultAPIBase
}

// AuthMethod is the interface for API authentication methods.
//
// Most users will use AuthKey.
type AuthMethod interface {
	modifyRequest(req *http.Request)
}

// APIKey is an AuthMethod for NewClient that authenticates requests
// using an authkey.
type APIKey string

func (ak APIKey) modifyRequest(req *http.Request) {
	req.SetBasicAuth(string(ak), "")
}

func (c *Client) setAuth(r *http.Request) {
	if c.auth != nil {
		c.auth.modifyRequest(r)
	}
}

// NewClient is a convenience method for instantiating a new Client.
//
// tailnet is the globally unique identifier for a Tailscale network, such
// as "example.com" or "user@gmail.com".
// If httpClient is nil, then http.DefaultClient is used.
// "api.tailscale.com" is set as the BaseURL for the returned client
// and can be changed manually by the user.
func NewClient(tailnet string, auth AuthMethod) *Client {
	return &Client{
		tailnet: tailnet,
		auth:    auth,
	}
}

func (c *Client) Tailnet() string { return c.tailnet }

// Do sends a raw HTTP request, after adding any authentication headers.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if !I_Acknowledge_This_API_Is_Unstable {
		return nil, errors.New("use of Client without setting I_Acknowledge_This_API_Is_Unstable")
	}
	c.setAuth(req)
	return c.httpClient().Do(req)
}

// sendRequest add the authentication key to the request and sends it. It
// receives the response and reads up to 10MB of it.
func (c *Client) sendRequest(req *http.Request) ([]byte, *http.Response, error) {
	if !I_Acknowledge_This_API_Is_Unstable {
		return nil, nil, errors.New("use of Client without setting I_Acknowledge_This_API_Is_Unstable")
	}
	c.setAuth(req)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, resp, err
	}
	defer resp.Body.Close()

	// Read response. Limit the response to 10MB.
	body := io.LimitReader(resp.Body, maxReadSize+1)
	b, err := io.ReadAll(body)
	if len(b) > maxReadSize {
		err = errors.New("API response too large")
	}
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
