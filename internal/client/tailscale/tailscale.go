// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tailscale provides a minimal control plane API client for internal
// use. A full client for 3rd party use is available at
// tailscale.com/client/tailscale/v2. The internal client is provided to avoid
// having to import that whole package.
package tailscale

import (
	tsclient "tailscale.com/client/tailscale"
)

func init() {
	tsclient.I_Acknowledge_This_API_Is_Unstable = true
}

// Client is an alias to tailscale.com/client/tailscale.
type Client = tsclient.Client

// AuthMethod is an alias to tailscale.com/client/tailscale.
type AuthMethod = tsclient.AuthMethod

// Device is an alias to tailscale.com/client/tailscale.
type Device = tsclient.Device

// DeviceFieldsOpts is an alias to tailscale.com/client/tailscale.
type DeviceFieldsOpts = tsclient.DeviceFieldsOpts

// Key is an alias to tailscale.com/client/tailscale.
type Key = tsclient.Key

// KeyCapabilities is an alias to tailscale.com/client/tailscale.
type KeyCapabilities = tsclient.KeyCapabilities

// KeyDeviceCapabilities is an alias to tailscale.com/client/tailscale.
type KeyDeviceCapabilities = tsclient.KeyDeviceCapabilities

// KeyDeviceCreateCapabilities is an alias to tailscale.com/client/tailscale.
type KeyDeviceCreateCapabilities = tsclient.KeyDeviceCreateCapabilities

// ErrResponse is an alias to tailscale.com/client/tailscale.
type ErrResponse = tsclient.ErrResponse

// NewClient is an alias to tailscale.com/client/tailscale.
func NewClient(tailnet string, auth AuthMethod) *Client {
	return tsclient.NewClient(tailnet, auth)
}
