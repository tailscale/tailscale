// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

// Package tailscale contains a Go client for the Tailscale control plane API.
//
// This package is only intended for internal and transitional use.
//
// Deprecated: the official control plane client is available at
// [tailscale.com/client/tailscale/v2].
package tailscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
)

// I_Acknowledge_This_API_Is_Unstable must be set true to use this package
// for now. This package is being replaced by [tailscale.com/client/tailscale/v2].
var I_Acknowledge_This_API_Is_Unstable = false

// TODO: use url.PathEscape() for deviceID and tailnets when constructing requests.

const defaultAPIBase = "https://api.tailscale.com"

// maxSize is the maximum read size (10MB) of responses from the server.
const maxReadSize = 10 << 20

// Client makes API calls to the Tailscale control plane API server.
//
// Use [NewClient] to instantiate one. Exported fields should be set before
// the client is used and not changed thereafter.
//
// Deprecated: use [tailscale.com/client/tailscale/v2] instead.
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
	// If nil, [http.DefaultClient] is used.
	HTTPClient *http.Client

	// UserAgent optionally specifies an alternate User-Agent header
	UserAgent string
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

// BuildURL builds a url to http(s)://<apiserver>/api/v2/<slash-separated-pathElements>
// using the given pathElements. It url escapes each path element, so the
// caller doesn't need to worry about that. The last item of pathElements can
// be of type url.Values to add a query string to the URL.
//
// For example, BuildURL(devices, 5) with the default server URL would result in
// https://api.tailscale.com/api/v2/devices/5.
func (c *Client) BuildURL(pathElements ...any) string {
	elem := make([]string, 1, len(pathElements)+1)
	elem[0] = "/api/v2"
	var query string
	for i, pathElement := range pathElements {
		if uv, ok := pathElement.(url.Values); ok && i == len(pathElements)-1 {
			query = uv.Encode()
		} else {
			elem = append(elem, url.PathEscape(fmt.Sprint(pathElement)))
		}
	}
	url := c.baseURL() + path.Join(elem...)
	if query != "" {
		url += "?" + query
	}
	return url
}

// BuildTailnetURL builds a url to http(s)://<apiserver>/api/v2/tailnet/<tailnet>/<slash-separated-pathElements>
// using the given pathElements. It url escapes each path element, so the
// caller doesn't need to worry about that. The last item of pathElements can
// be of type url.Values to add a query string to the URL.
//
// For example, BuildTailnetURL(policy, validate) with the default server URL and a tailnet of "example.com"
// would result in https://api.tailscale.com/api/v2/tailnet/example.com/policy/validate.
func (c *Client) BuildTailnetURL(pathElements ...any) string {
	allElements := make([]any, 2, len(pathElements)+2)
	allElements[0] = "tailnet"
	allElements[1] = c.tailnet
	allElements = append(allElements, pathElements...)
	return c.BuildURL(allElements...)
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

// APIKey is an [AuthMethod] for [NewClient] that authenticates requests
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

// NewClient is a convenience method for instantiating a new [Client].
//
// tailnet is the globally unique identifier for a Tailscale network, such
// as "example.com" or "user@gmail.com".
// If httpClient is nil, then [http.DefaultClient] is used.
// "api.tailscale.com" is set as the BaseURL for the returned client
// and can be changed manually by the user.
//
// Deprecated: use [tailscale.com/client/tailscale/v2] instead.
func NewClient(tailnet string, auth AuthMethod) *Client {
	return &Client{
		tailnet:   tailnet,
		auth:      auth,
		UserAgent: "tailscale-client-oss",
	}
}

func (c *Client) Tailnet() string { return c.tailnet }

// Do sends a raw HTTP request, after adding any authentication headers.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if !I_Acknowledge_This_API_Is_Unstable {
		return nil, errors.New("use of Client without setting I_Acknowledge_This_API_Is_Unstable")
	}
	c.setAuth(req)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	return c.httpClient().Do(req)
}

// sendRequest add the authentication key to the request and sends it. It
// receives the response and reads up to 10MB of it.
func (c *Client) sendRequest(req *http.Request) ([]byte, *http.Response, error) {
	resp, err := c.Do(req)
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

// HandleErrorResponse decodes the error message from the server and returns
// an [ErrResponse] from it.
//
// Deprecated: use [tailscale.com/client/tailscale/v2] instead.
func HandleErrorResponse(b []byte, resp *http.Response) error {
	var errResp ErrResponse
	if err := json.Unmarshal(b, &errResp); err != nil {
		return fmt.Errorf("json.Unmarshal %q: %w", b, err)
	}
	errResp.Status = resp.StatusCode
	return errResp
}
