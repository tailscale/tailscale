// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package tsclient provides a mockable wrapper around the tailscale-client-go-v2 package for use by the Kubernetes
// operator. It also contains the Provider type used to manage multiple instances of tailscale clients for different
// tailnets.
package tsclient

import (
	"context"

	"tailscale.com/client/tailscale/v2"
)

type (
	// The Client interface describes types that interact with the Tailscale API.
	Client interface {
		// LoginURL should return the url of the Tailscale control plane.
		LoginURL() string
		// Devices should return a DeviceResource implementation used to interact with the devices API.
		Devices() DeviceResource
		// Keys should return a KeyResource implementation used to interact with the keys API.
		Keys() KeyResource
		// VIPServices should return a VIPServiceResource implementation used to interact with the VIP services API.
		VIPServices() VIPServiceResource
	}

	// The DeviceResource interface describes types that expose device related API endpoints.
	DeviceResource interface {
		// Delete should delete a device with a matching id.
		Delete(ctx context.Context, id string) error
		// List should return all devices based on the specified options.
		List(ctx context.Context, opts ...tailscale.ListDevicesOptions) ([]tailscale.Device, error)
		// Get should return the device with the matching identifier.
		Get(ctx context.Context, id string) (*tailscale.Device, error)
	}

	// The KeyResource interface describes types that expose key related API endpoints.
	KeyResource interface {
		// CreateAuthKey should create and return a new auth key used to authenticate a device.
		CreateAuthKey(ctx context.Context, ckr tailscale.CreateKeyRequest) (*tailscale.Key, error)
		// List should return keys created by the caller or all keys if the provided boolean is set to true.
		List(ctx context.Context, all bool) ([]tailscale.Key, error)
	}

	// The VIPServiceResource interface describes types that expose vip service related API endpoints.
	VIPServiceResource interface {
		// List should return all existing vip services within the tailnet.
		List(ctx context.Context) ([]tailscale.VIPService, error)
		// Delete should remove a named service from the tailnet.
		Delete(ctx context.Context, name string) error
		// Get should return the vip service associated with the given name.
		Get(ctx context.Context, name string) (*tailscale.VIPService, error)
		// CreateOrUpdate should update the provided vip service, creating it if it does not exist.
		CreateOrUpdate(ctx context.Context, svc tailscale.VIPService) error
	}

	clientWrapper struct {
		loginURL string
		client   *tailscale.Client
	}
)

// Wrap converts a given tailscale.Client into a Client.
func Wrap(client *tailscale.Client) Client {
	return &clientWrapper{client: client, loginURL: client.BaseURL.String()}
}

func (c *clientWrapper) Devices() DeviceResource {
	return c.client.Devices()
}

func (c *clientWrapper) Keys() KeyResource {
	return c.client.Keys()
}

func (c *clientWrapper) VIPServices() VIPServiceResource {
	return c.client.VIPServices()
}

func (c *clientWrapper) LoginURL() string {
	return c.loginURL
}
