// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.19

package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"tailscale.com/client/tailscale/apitype"
)

// DNSNameServers is returned when retrieving the list of nameservers.
// It is also the structure provided when setting nameservers.
type DNSNameServers struct {
	DNS []string `json:"dns"` // DNS name servers
}

// DNSNameServersPostResponse is returned when setting the list of DNS nameservers.
//
// It includes the MagicDNS status since nameservers changes may affect MagicDNS.
type DNSNameServersPostResponse struct {
	DNS      []string `json:"dns"`      // DNS name servers
	MagicDNS bool     `json:"magicDNS"` // whether MagicDNS is active for this tailnet (enabled + has fallback nameservers)
}

// DNSSearchpaths is the list of search paths for a given domain.
type DNSSearchPaths struct {
	SearchPaths []string `json:"searchPaths"` // DNS search paths
}

// DNSPreferences is the preferences set for a given tailnet.
//
// It includes MagicDNS which can be turned on or off. To enable MagicDNS,
// there must be at least one nameserver. When all nameservers are removed,
// MagicDNS is disabled.
type DNSPreferences struct {
	MagicDNS bool `json:"magicDNS"` // whether MagicDNS is active for this tailnet (enabled + has fallback nameservers)
}

func (c *Client) dnsGETRequest(ctx context.Context, endpoint string) ([]byte, error) {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/dns/%s", c.baseURL(), c.tailnet, endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}

	return b, nil
}

func (c *Client) dnsPOSTRequest(ctx context.Context, endpoint string, postData any) ([]byte, error) {
	path := fmt.Sprintf("%s/api/v2/tailnet/%s/dns/%s", c.baseURL(), c.tailnet, endpoint)
	data, err := json.Marshal(&postData)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return nil, err
	}

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}

	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}

	return b, nil
}

// DNSConfig retrieves the DNSConfig settings for a domain.
func (c *Client) DNSConfig(ctx context.Context) (cfg *apitype.DNSConfig, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.DNSConfig: %w", err)
		}
	}()
	b, err := c.dnsGETRequest(ctx, "config")
	if err != nil {
		return nil, err
	}
	var dnsResp apitype.DNSConfig
	err = json.Unmarshal(b, &dnsResp)
	return &dnsResp, err
}

func (c *Client) SetDNSConfig(ctx context.Context, cfg apitype.DNSConfig) (resp *apitype.DNSConfig, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.SetDNSConfig: %w", err)
		}
	}()
	var dnsResp apitype.DNSConfig
	b, err := c.dnsPOSTRequest(ctx, "config", cfg)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &dnsResp)
	return &dnsResp, err
}

// NameServers retrieves the list of nameservers set for a domain.
func (c *Client) NameServers(ctx context.Context) (nameservers []string, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.NameServers: %w", err)
		}
	}()
	b, err := c.dnsGETRequest(ctx, "nameservers")
	if err != nil {
		return nil, err
	}
	var dnsResp DNSNameServers
	err = json.Unmarshal(b, &dnsResp)
	return dnsResp.DNS, err
}

// SetNameServers sets the list of nameservers for a tailnet to the list provided
// by the user.
//
// It returns the new list of nameservers and the MagicDNS status in case it was
// affected by the change. For example, removing all nameservers will turn off
// MagicDNS.
func (c *Client) SetNameServers(ctx context.Context, nameservers []string) (dnsResp *DNSNameServersPostResponse, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.SetNameServers: %w", err)
		}
	}()
	dnsReq := DNSNameServers{DNS: nameservers}
	b, err := c.dnsPOSTRequest(ctx, "nameservers", dnsReq)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &dnsResp)
	return dnsResp, err
}

// DNSPreferences retrieves the DNS preferences set for a tailnet.
//
// It returns the status of MagicDNS.
func (c *Client) DNSPreferences(ctx context.Context) (dnsResp *DNSPreferences, err error) {
	// Format return errors to be descriptive.
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.DNSPreferences: %w", err)
		}
	}()
	b, err := c.dnsGETRequest(ctx, "preferences")
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(b, &dnsResp)
	return dnsResp, err
}

// SetDNSPreferences sets the DNS preferences for a tailnet.
//
// MagicDNS can only be enabled when there is at least one nameserver provided.
// When all nameservers are removed, MagicDNS is disabled and will stay disabled,
// unless explicitly enabled by a user again.
func (c *Client) SetDNSPreferences(ctx context.Context, magicDNS bool) (dnsResp *DNSPreferences, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.SetDNSPreferences: %w", err)
		}
	}()
	dnsReq := DNSPreferences{MagicDNS: magicDNS}
	b, err := c.dnsPOSTRequest(ctx, "preferences", dnsReq)
	if err != nil {
		return
	}
	err = json.Unmarshal(b, &dnsResp)
	return dnsResp, err
}

// SearchPaths retrieves the list of searchpaths set for a tailnet.
func (c *Client) SearchPaths(ctx context.Context) (searchpaths []string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.SearchPaths: %w", err)
		}
	}()
	b, err := c.dnsGETRequest(ctx, "searchpaths")
	if err != nil {
		return nil, err
	}
	var dnsResp *DNSSearchPaths
	err = json.Unmarshal(b, &dnsResp)
	return dnsResp.SearchPaths, err
}

// SetSearchPaths sets the list of searchpaths for a tailnet.
func (c *Client) SetSearchPaths(ctx context.Context, searchpaths []string) (newSearchPaths []string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.SetSearchPaths: %w", err)
		}
	}()
	dnsReq := DNSSearchPaths{SearchPaths: searchpaths}
	b, err := c.dnsPOSTRequest(ctx, "searchpaths", dnsReq)
	if err != nil {
		return nil, err
	}
	var dnsResp DNSSearchPaths
	err = json.Unmarshal(b, &dnsResp)
	return dnsResp.SearchPaths, err
}
