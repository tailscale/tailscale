// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"tailscale.com/tailcfg"
	"tailscale.com/util/httpm"
)

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
	// Annotations are optional key-value pairs that can be used to store arbitrary metadata.
	Annotations map[string]string `json:"annotations,omitempty"`
	// Ports are the ports of a VIPService that will be configured via Tailscale serve config.
	// If set, any node wishing to advertise this VIPService must have this port configured via Tailscale serve.
	Ports []string `json:"ports,omitempty"`
	// Tags are optional ACL tags that will be applied to the VIPService.
	Tags []string `json:"tags,omitempty"`
}

// GetVIPService retrieves a VIPService by its name. It returns 404 if the VIPService is not found.
func (client *Client) GetVIPService(ctx context.Context, name tailcfg.ServiceName) (*VIPService, error) {
	path := client.BuildTailnetURL("vip-services", name.String())
	req, err := http.NewRequestWithContext(ctx, httpm.GET, path, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating new HTTP request: %w", err)
	}
	b, resp, err := SendRequest(client, req)
	if err != nil {
		return nil, fmt.Errorf("error making Tailsale API request: %w", err)
	}
	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return nil, HandleErrorResponse(b, resp)
	}
	svc := &VIPService{}
	if err := json.Unmarshal(b, svc); err != nil {
		return nil, err
	}
	return svc, nil
}

// CreateOrUpdateVIPService creates or updates a VIPService by its name. Caller must ensure that, if the
// VIPService already exists, the VIPService is fetched first to ensure that any auto-allocated IP addresses are not
// lost during the update. If the VIPService was created without any IP addresses explicitly set (so that they were
// auto-allocated by Tailscale) any subsequent request to this function that does not set any IP addresses will error.
func (client *Client) CreateOrUpdateVIPService(ctx context.Context, svc *VIPService) error {
	data, err := json.Marshal(svc)
	if err != nil {
		return err
	}
	path := client.BuildTailnetURL("vip-services", svc.Name.String())
	req, err := http.NewRequestWithContext(ctx, httpm.PUT, path, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("error creating new HTTP request: %w", err)
	}
	b, resp, err := SendRequest(client, req)
	if err != nil {
		return fmt.Errorf("error making Tailscale API request: %w", err)
	}
	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return HandleErrorResponse(b, resp)
	}
	return nil
}

// DeleteVIPService deletes a VIPService by its name. It returns an error if the VIPService
// does not exist or if the deletion fails.
func (client *Client) DeleteVIPService(ctx context.Context, name tailcfg.ServiceName) error {
	path := client.BuildTailnetURL("vip-services", name.String())
	req, err := http.NewRequestWithContext(ctx, httpm.DELETE, path, nil)
	if err != nil {
		return fmt.Errorf("error creating new HTTP request: %w", err)
	}
	b, resp, err := SendRequest(client, req)
	if err != nil {
		return fmt.Errorf("error making Tailscale API request: %w", err)
	}
	// If status code was not successful, return the error.
	if resp.StatusCode != http.StatusOK {
		return HandleErrorResponse(b, resp)
	}
	return nil
}
