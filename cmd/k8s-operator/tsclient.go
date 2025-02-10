// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
	"tailscale.com/tailcfg"
	"tailscale.com/util/httpm"
)

// defaultTailnet is a value that can be used in Tailscale API calls instead of tailnet name to indicate that the API
// call should be performed on the default tailnet for the provided credentials.
const (
	defaultTailnet = "-"
	defaultBaseURL = "https://api.tailscale.com"
)

func newTSClient(ctx context.Context, clientIDPath, clientSecretPath string) (tsClient, error) {
	clientID, err := os.ReadFile(clientIDPath)
	if err != nil {
		return nil, fmt.Errorf("error reading client ID %q: %w", clientIDPath, err)
	}
	clientSecret, err := os.ReadFile(clientSecretPath)
	if err != nil {
		return nil, fmt.Errorf("reading client secret %q: %w", clientSecretPath, err)
	}
	credentials := clientcredentials.Config{
		ClientID:     string(clientID),
		ClientSecret: string(clientSecret),
		TokenURL:     "https://login.tailscale.com/api/v2/oauth/token",
	}
	c := tailscale.NewClient(defaultTailnet, nil)
	c.UserAgent = "tailscale-k8s-operator"
	c.HTTPClient = credentials.Client(ctx)
	tsc := &tsClientImpl{
		Client:  c,
		baseURL: defaultBaseURL,
		tailnet: defaultTailnet,
	}
	return tsc, nil
}

type tsClient interface {
	CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error)
	Device(ctx context.Context, deviceID string, fields *tailscale.DeviceFieldsOpts) (*tailscale.Device, error)
	DeleteDevice(ctx context.Context, nodeStableID string) error
	getVIPService(ctx context.Context, name tailcfg.ServiceName) (*VIPService, error)
	createOrUpdateVIPService(ctx context.Context, svc *VIPService) error
	deleteVIPService(ctx context.Context, name tailcfg.ServiceName) error
}

type tsClientImpl struct {
	*tailscale.Client
	baseURL string
	tailnet string
}

// VIPService is a Tailscale VIPService with Tailscale API JSON representation.
type VIPService struct {
	// Name is a VIPService name in form svc:<leftmost-label-of-service-DNS-name>.
	Name tailcfg.ServiceName `json:"name,omitempty"`
	// Addrs are the IP addresses of the VIP Service. There are two addresses:
	// the first is IPv4 and the second is IPv6.
	// When creating a new VIP Service, the IP addresses are optional: if no
	// addresses are specified then they will be selected. If an IPv4 address is
	// specified at index 0, then that address will attempt to be used. An IPv6
	// address can not be specified upon creation.
	Addrs []string `json:"addrs,omitempty"`
	// Comment is an optional text string for display in the admin panel.
	Comment string `json:"comment,omitempty"`
	// Ports are the ports of a VIPService that will be configured via Tailscale serve config.
	// If set, any node wishing to advertise this VIPService must have this port configured via Tailscale serve.
	Ports []string `json:"ports,omitempty"`
	// Tags are optional ACL tags that will be applied to the VIPService.
	Tags []string `json:"tags,omitempty"`
}

// GetVIPServiceByName retrieves a VIPService by its name. It returns 404 if the VIPService is not found.
func (c *tsClientImpl) getVIPService(ctx context.Context, name tailcfg.ServiceName) (*VIPService, error) {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/vip-services/%s", c.baseURL, c.tailnet, url.PathEscape(name.String()))
	req, err := http.NewRequestWithContext(ctx, httpm.GET, path, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating new HTTP request: %w", err)
	}
	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error making Tailsale API request: %w", err)
	}
	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}
	svc := &VIPService{}
	if err := json.Unmarshal(b, svc); err != nil {
		return nil, err
	}
	return svc, nil
}

// createOrUpdateVIPService creates or updates a VIPService by its name. Caller must ensure that, if the
// VIPService already exists, the VIPService is fetched first to ensure that any auto-allocated IP addresses are not
// lost during the update. If the VIPService was created without any IP addresses explicitly set (so that they were
// auto-allocated by Tailscale) any subsequent request to this function that does not set any IP addresses will error.
func (c *tsClientImpl) createOrUpdateVIPService(ctx context.Context, svc *VIPService) error {
	data, err := json.Marshal(svc)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/vip-services/%s", c.baseURL, c.tailnet, url.PathEscape(svc.Name.String()))
	req, err := http.NewRequestWithContext(ctx, httpm.PUT, path, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("error creating new HTTP request: %w", err)
	}
	b, resp, err := c.sendRequest(req)
	if err != nil {
		return fmt.Errorf("error making Tailscale API request: %w", err)
	}
	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return handleErrorResponse(b, resp)
	}
	return nil
}

// DeleteVIPServiceByName deletes a VIPService by its name. It returns an error if the VIPService
// does not exist or if the deletion fails.
func (c *tsClientImpl) deleteVIPService(ctx context.Context, name tailcfg.ServiceName) error {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/vip-services/%s", c.baseURL, c.tailnet, url.PathEscape(name.String()))
	req, err := http.NewRequestWithContext(ctx, httpm.DELETE, path, nil)
	if err != nil {
		return fmt.Errorf("error creating new HTTP request: %w", err)
	}
	b, resp, err := c.sendRequest(req)
	if err != nil {
		return fmt.Errorf("error making Tailscale API request: %w", err)
	}
	// If status code was not successful, return the error.
	if resp.StatusCode != http.StatusOK {
		return handleErrorResponse(b, resp)
	}
	return nil
}

// sendRequest add the authentication key to the request and sends it. It
// receives the response and reads up to 10MB of it.
func (c *tsClientImpl) sendRequest(req *http.Request) ([]byte, *http.Response, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, resp, fmt.Errorf("error actually doing request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("error reading response body: %v", err)
	}
	return b, resp, err
}

// handleErrorResponse decodes the error message from the server and returns
// an ErrResponse from it.
func handleErrorResponse(b []byte, resp *http.Response) error {
	var errResp tailscale.ErrResponse
	if err := json.Unmarshal(b, &errResp); err != nil {
		return err
	}
	errResp.Status = resp.StatusCode
	return errResp
}
