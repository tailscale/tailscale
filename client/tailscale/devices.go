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
	"net/url"

	"tailscale.com/types/opt"
)

type GetDevicesResponse struct {
	Devices []*Device `json:"devices"`
}

type DerpRegion struct {
	Preferred           bool    `json:"preferred,omitempty"`
	LatencyMilliseconds float64 `json:"latencyMs"`
}

type ClientConnectivity struct {
	Endpoints             []string `json:"endpoints"`
	DERP                  string   `json:"derp"`
	MappingVariesByDestIP opt.Bool `json:"mappingVariesByDestIP"`
	// DERPLatency is mapped by region name (e.g. "New York City", "Seattle").
	DERPLatency    map[string]DerpRegion `json:"latency"`
	ClientSupports map[string]opt.Bool   `json:"clientSupports"`
}

type Device struct {
	// Addresses is a list of the devices's Tailscale IP addresses.
	// It's currently just 1 element, the 100.x.y.z Tailscale IP.
	Addresses []string `json:"addresses"`
	DeviceID  string   `json:"id"`
	User      string   `json:"user"`
	Name      string   `json:"name"`
	Hostname  string   `json:"hostname"`

	ClientVersion     string   `json:"clientVersion"`   // Empty for external devices.
	UpdateAvailable   bool     `json:"updateAvailable"` // Empty for external devices.
	OS                string   `json:"os"`
	Tags              []string `json:"tags"`
	Created           string   `json:"created"` // Empty for external devices.
	LastSeen          string   `json:"lastSeen"`
	KeyExpiryDisabled bool     `json:"keyExpiryDisabled"`
	Expires           string   `json:"expires"`
	Authorized        bool     `json:"authorized"`
	IsExternal        bool     `json:"isExternal"`
	MachineKey        string   `json:"machineKey"` // Empty for external devices.
	NodeKey           string   `json:"nodeKey"`

	// BlocksIncomingConnections is configured via the device's
	// Tailscale client preferences. This field is only reported
	// to the API starting with Tailscale 1.3.x clients.
	BlocksIncomingConnections bool `json:"blocksIncomingConnections"`

	// The following fields are not included by default:

	// EnabledRoutes are the previously-approved subnet routes
	// (e.g. "192.168.4.16/24", "10.5.2.4/32").
	EnabledRoutes []string `json:"enabledRoutes"` // Empty for external devices.
	// AdvertisedRoutes are the subnets (both enabled and not enabled)
	// being requested from the node.
	AdvertisedRoutes []string `json:"advertisedRoutes"` // Empty for external devices.

	ClientConnectivity *ClientConnectivity `json:"clientConnectivity"`

	// PostureIdentity contains extra identifiers collected from the device when
	// the tailnet has the device posture identification features enabled. If
	// Tailscale have attempted to collect this from the device but it has not
	// opted in, PostureIdentity will have Disabled=true.
	PostureIdentity *DevicePostureIdentity `json:"postureIdentity"`
}

type DevicePostureIdentity struct {
	Disabled      bool     `json:"disabled,omitempty"`
	SerialNumbers []string `json:"serialNumbers,omitempty"`
}

// DeviceFieldsOpts determines which fields should be returned in the response.
//
// Please only use DeviceAllFields and DeviceDefaultFields.
// Other DeviceFieldsOpts are not supported.
//
// TODO: Support other DeviceFieldsOpts.
// In the future, users should be able to create their own DeviceFieldsOpts
// as valid arguments by setting the fields they want returned to a "non-nil"
// value. For example, DeviceFieldsOpts{NodeID: "true"} should only return NodeIDs.
type DeviceFieldsOpts Device

func (d *DeviceFieldsOpts) addFieldsToQueryParameter() string {
	if d == DeviceDefaultFields || d == nil {
		return "default"
	}
	if d == DeviceAllFields {
		return "all"
	}

	return ""
}

var (
	DeviceAllFields = &DeviceFieldsOpts{}

	// DeviceDefaultFields specifies that the following fields are returned:
	//   Addresses, NodeID, User, Name, Hostname, ClientVersion, UpdateAvailable,
	//   OS, Created, LastSeen, KeyExpiryDisabled, Expires, Authorized, IsExternal
	//   MachineKey, NodeKey, BlocksIncomingConnections.
	DeviceDefaultFields = &DeviceFieldsOpts{}
)

// Devices retrieves the list of devices for a tailnet.
//
// See the Device structure for the list of fields hidden for external devices.
// The optional fields parameter specifies which fields of the devices to return; currently
// only DeviceDefaultFields (equivalent to nil) and DeviceAllFields are supported.
// Other values are currently undefined.
func (c *Client) Devices(ctx context.Context, fields *DeviceFieldsOpts) (deviceList []*Device, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.Devices: %w", err)
		}
	}()

	path := fmt.Sprintf("%s/api/v2/tailnet/%s/devices", c.baseURL(), c.tailnet)
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	// Add fields.
	fieldStr := fields.addFieldsToQueryParameter()
	q := req.URL.Query()
	q.Add("fields", fieldStr)
	req.URL.RawQuery = q.Encode()

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}

	var devices GetDevicesResponse
	err = json.Unmarshal(b, &devices)
	return devices.Devices, err
}

// Device retrieved the details for a specific device.
//
// See the Device structure for the list of fields hidden for an external device.
// The optional fields parameter specifies which fields of the devices to return; currently
// only DeviceDefaultFields (equivalent to nil) and DeviceAllFields are supported.
// Other values are currently undefined.
func (c *Client) Device(ctx context.Context, deviceID string, fields *DeviceFieldsOpts) (device *Device, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.Device: %w", err)
		}
	}()
	path := fmt.Sprintf("%s/api/v2/device/%s", c.baseURL(), deviceID)
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}

	// Add fields.
	fieldStr := fields.addFieldsToQueryParameter()
	q := req.URL.Query()
	q.Add("fields", fieldStr)
	req.URL.RawQuery = q.Encode()

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return nil, handleErrorResponse(b, resp)
	}

	err = json.Unmarshal(b, &device)
	return device, err
}

// DeleteDevice deletes the specified device from the Client's tailnet.
// NOTE: Only devices that belong to the Client's tailnet can be deleted.
// Deleting external devices is not supported.
func (c *Client) DeleteDevice(ctx context.Context, deviceID string) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("tailscale.DeleteDevice: %w", err)
		}
	}()

	path := fmt.Sprintf("%s/api/v2/device/%s", c.baseURL(), url.PathEscape(deviceID))
	req, err := http.NewRequestWithContext(ctx, "DELETE", path, nil)
	if err != nil {
		return err
	}

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}
	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return handleErrorResponse(b, resp)
	}
	return nil
}

// AuthorizeDevice marks a device as authorized.
func (c *Client) AuthorizeDevice(ctx context.Context, deviceID string) error {
	return c.SetAuthorized(ctx, deviceID, true)
}

// SetAuthorized marks a device as authorized or not.
func (c *Client) SetAuthorized(ctx context.Context, deviceID string, authorized bool) error {
	params := &struct {
		Authorized bool `json:"authorized"`
	}{Authorized: authorized}
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("%s/api/v2/device/%s/authorized", c.baseURL(), url.PathEscape(deviceID))
	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}
	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return handleErrorResponse(b, resp)
	}

	return nil
}

// SetTags updates the ACL tags on a device.
func (c *Client) SetTags(ctx context.Context, deviceID string, tags []string) error {
	params := &struct {
		Tags []string `json:"tags"`
	}{Tags: tags}
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	path := fmt.Sprintf("%s/api/v2/device/%s/tags", c.baseURL(), url.PathEscape(deviceID))
	req, err := http.NewRequestWithContext(ctx, "POST", path, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	b, resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}
	// If status code was not successful, return the error.
	// TODO: Change the check for the StatusCode to include other 2XX success codes.
	if resp.StatusCode != http.StatusOK {
		return handleErrorResponse(b, resp)
	}

	return nil
}
