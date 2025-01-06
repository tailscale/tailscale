// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"

	"tailscale.com/net/tsaddr"
	"tailscale.com/util/httpm"
)

// VIPService is a Tailscale VIPService with Tailscale API JSON representation.
type VIPService struct {
	// Name is the leftmost label of the DNS name of the VIP service.
	// Name is required.
	Name string `json:"name,omitempty"`
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
func (c *Client) GetVIPServiceByName(ctx context.Context, name string) (*VIPService, error) {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/vip-services/by-name/%s", c.baseURL(), c.tailnet, url.PathEscape(name))
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

// CreateOrUpdateVIPServiceByName creates or updates a VIPService by its name. Caller must ensure that, if the
// VIPService already exists, the VIPService is fetched first to ensure that any auto-allocated IP addresses are not
// lost during the update. If the VIPService was created without any IP addresses explicitly set (so that they were
// auto-allocated by Tailscale) any subsequent request to this function that does not set any IP addresses will error.
func (c *Client) CreateOrUpdateVIPServiceByName(ctx context.Context, svc *VIPService) error {
	if err := svc.validateVIPService(); err != nil {
		return fmt.Errorf("invalid VIP service: %w", err)
	}

	data, err := json.Marshal(svc)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/vip-services/by-name/%s", c.baseURL(), c.tailnet, url.PathEscape(svc.Name))
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
func (c *Client) DeleteVIPServiceByName(ctx context.Context, name string) error {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/vip-services/by-name/%s", c.baseURL(), c.tailnet, url.PathEscape(name))
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

// validateVIPService checks if the VIPService is a valid Tailscale VIPService.
func (svc *VIPService) validateVIPService() error {
	if svc.Name == "" {
		return fmt.Errorf("VIPService name is required")
	}
	if err := dnsname.ValidLabel(svc.Name); err != nil {
		return fmt.Errorf("invalid VIPService name: name must be a valid DNS label: %w", err)
	}

	for _, tag := range svc.Tags {
		if err := tailcfg.CheckTag(tag); err != nil {
			return fmt.Errorf("invalid tag %q: %w", tag, err)
		}
	}

	// At most 2 addresses are allowed.
	// The first address must be a valid Tailscale IPv4 address and the second address must be a valid IPv6 address.
	if len(svc.Addrs) > 0 {
		// Validate first address (must be IPv4)
		addr, err := netip.ParseAddr(svc.Addrs[0])
		if err != nil {
			return fmt.Errorf("invalid IP address at index 0: %q", svc.Addrs[0])
		}
		if !addr.Is4() {
			return fmt.Errorf("first IP address must be IPv4")
		}
		if !tsaddr.IsTailscaleIP(addr) {
			return fmt.Errorf("IP address %q is not a valid Tailscale IP", svc.Addrs[0])
		}

		if len(svc.Addrs) > 2 {
			return fmt.Errorf("VIP services can have at most 2 IP addresses, got %d", len(svc.Addrs))
		}
		if len(svc.Addrs) == 2 {
			addr, err := netip.ParseAddr(svc.Addrs[1])
			if err != nil {
				return fmt.Errorf("invalid IP address at index 1: %q", svc.Addrs[1])
			}
			if !addr.Is6() {
				return fmt.Errorf("second IP address must be IPv6, got %q", svc.Addrs[1])
			}
		}
	}

	return nil
}
