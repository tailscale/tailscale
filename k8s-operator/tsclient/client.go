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

	DeviceResource interface {
		Delete(context.Context, string) error
		List(context.Context, ...tailscale.ListDevicesOptions) ([]tailscale.Device, error)
		Get(context.Context, string) (*tailscale.Device, error)
	}

	KeyResource interface {
		CreateAuthKey(ctx context.Context, ckr tailscale.CreateKeyRequest) (*tailscale.Key, error)
		List(ctx context.Context, all bool) ([]tailscale.Key, error)
	}

	VIPServiceResource interface {
		List(ctx context.Context) ([]tailscale.VIPService, error)
		Delete(ctx context.Context, name string) error
		Get(ctx context.Context, name string) (*tailscale.VIPService, error)
		CreateOrUpdate(ctx context.Context, svc tailscale.VIPService) error
	}

	clientWrapper struct {
		loginURL string
		client   *tailscale.Client
	}
)

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
