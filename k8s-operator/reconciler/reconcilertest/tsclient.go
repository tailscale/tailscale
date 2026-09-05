// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package reconcilertest

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"

	tailscaleclient "tailscale.com/client/tailscale/v2"

	"tailscale.com/k8s-operator/tsclient"
)

// FakeClient is a tsclient.Client that records the calls a reconciler makes to the Tailscale API and serves canned
// responses. The zero value is usable: keys are minted with generated values, no devices exist, and the login URL is
// blank. FakeClient is safe for concurrent use.
//
// Only the endpoints the reconcilers actually call are implemented. Anything else panics via the embedded nil
// interface rather than silently returning a zero value, so a reconciler that starts calling a new endpoint fails
// loudly instead of being tested against a fake that quietly does nothing.
type FakeClient struct {
	tsclient.Client

	mu sync.Mutex

	loginURL string

	// Devices are returned by Devices().Get and List. Get matches on Device.ID and returns a 404 API error when no
	// device matches, mirroring control's behaviour for an unknown or already-deleted device.
	devices []tailscaleclient.Device

	// nextKeys are handed out by CreateAuthKey in order. Once exhausted, generated values are returned instead, so
	// tests only script the keys they assert on.
	nextKeys []string

	keyCalls      []tailscaleclient.CreateKeyRequest
	deviceDeletes []string
}

// FakeClientOption configures a FakeClient.
type FakeClientOption func(*FakeClient)

// WithLoginURL sets the URL returned by LoginURL, which reconcilers embed in the workloads they create.
func WithLoginURL(url string) FakeClientOption {
	return func(c *FakeClient) { c.loginURL = url }
}

// WithAuthKeys sets the auth keys CreateAuthKey returns, in order. Use it when a test needs to tell successive keys
// apart, e.g. to assert that a replica picked up a reissued key.
func WithAuthKeys(keys ...string) FakeClientOption {
	return func(c *FakeClient) { c.nextKeys = keys }
}

// NewFakeClient returns a FakeClient configured by opts.
func NewFakeClient(opts ...FakeClientOption) *FakeClient {
	c := &FakeClient{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// LoginURL implements tsclient.Client.
func (c *FakeClient) LoginURL() string { return c.loginURL }

// Devices implements tsclient.Client.
func (c *FakeClient) Devices() tsclient.DeviceResource { return (*fakeDevices)(c) }

// Keys implements tsclient.Client.
func (c *FakeClient) Keys() tsclient.KeyResource { return (*fakeKeys)(c) }

// CreateAuthKeyCalls returns every auth key request the reconciler has made, in order.
func (c *FakeClient) CreateAuthKeyCalls() []tailscaleclient.CreateKeyRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.keyCalls)
}

// DeviceDeletes returns the IDs of every device the reconciler has deleted, in order.
func (c *FakeClient) DeviceDeletes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.deviceDeletes)
}

// SetDevices replaces the devices served by the fake. Use it to simulate control catching up partway through a test,
// e.g. once a replica has authenticated.
func (c *FakeClient) SetDevices(devices ...tailscaleclient.Device) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.devices = devices
}

type fakeDevices FakeClient

func (d *fakeDevices) Delete(_ context.Context, id string) error {
	c := (*FakeClient)(d)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deviceDeletes = append(c.deviceDeletes, id)
	return nil
}

func (d *fakeDevices) List(_ context.Context, _ ...tailscaleclient.ListDevicesOptions) ([]tailscaleclient.Device, error) {
	c := (*FakeClient)(d)
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.devices), nil
}

func (d *fakeDevices) Get(_ context.Context, id string) (*tailscaleclient.Device, error) {
	c := (*FakeClient)(d)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, dev := range c.devices {
		if dev.ID == id {
			return &dev, nil
		}
	}
	return nil, tailscaleclient.APIError{Status: http.StatusNotFound}
}

type fakeKeys FakeClient

func (k *fakeKeys) CreateAuthKey(_ context.Context, req tailscaleclient.CreateKeyRequest) (*tailscaleclient.Key, error) {
	c := (*FakeClient)(k)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyCalls = append(c.keyCalls, req)

	var key string
	if len(c.nextKeys) > 0 {
		key, c.nextKeys = c.nextKeys[0], c.nextKeys[1:]
	} else {
		key = fmt.Sprintf("auth-key-%d", len(c.keyCalls))
	}
	return &tailscaleclient.Key{Key: key}, nil
}

func (k *fakeKeys) List(_ context.Context, _ bool) ([]tailscaleclient.Key, error) {
	return nil, nil
}

// FakeClientProvider is a tailscaled.ClientProvider that hands out a single client for every tailnet, or fails with a
// fixed error. Reconcilers resolve their API client through a provider, so tests that exercise the
// tailnet-unavailable path need one that can fail.
type FakeClientProvider struct {
	client tsclient.Client
	err    error
}

// NewFakeClientProvider returns a provider that resolves every tailnet to client.
func NewFakeClientProvider(client tsclient.Client) *FakeClientProvider {
	return &FakeClientProvider{client: client}
}

// NewFailingClientProvider returns a provider that fails to resolve any tailnet with err.
func NewFailingClientProvider(err error) *FakeClientProvider {
	return &FakeClientProvider{err: err}
}

// For implements tailscaled.ClientProvider.
func (p *FakeClientProvider) For(_ string) (tsclient.Client, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.client, nil
}
