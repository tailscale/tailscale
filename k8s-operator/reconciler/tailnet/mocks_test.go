// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailnet_test

import (
	"context"
	"io"

	"tailscale.com/client/tailscale/v2"

	"tailscale.com/k8s-operator/tsclient"
)

type (
	MockTailnetClient struct {
		ErrorOnDevices  bool
		ErrorOnKeys     bool
		ErrorOnServices bool
	}

	MockDeviceResource struct {
		tsclient.DeviceResource

		Error bool
	}

	MockKeyResource struct {
		tsclient.KeyResource

		Error bool
	}

	MockVIPServiceResource struct {
		tsclient.VIPServiceResource

		Error bool
	}
)

func (m MockKeyResource) List(_ context.Context, _ bool) ([]tailscale.Key, error) {
	if m.Error {
		return nil, io.EOF
	}

	return nil, nil
}

func (m MockDeviceResource) List(_ context.Context, _ ...tailscale.ListDevicesOptions) ([]tailscale.Device, error) {
	if m.Error {
		return nil, io.EOF
	}

	return nil, nil
}

func (m MockVIPServiceResource) List(_ context.Context) ([]tailscale.VIPService, error) {
	if m.Error {
		return nil, io.EOF
	}

	return nil, nil
}

func (m MockTailnetClient) Devices() tsclient.DeviceResource {
	return MockDeviceResource{Error: m.ErrorOnDevices}
}

func (m MockTailnetClient) Keys() tsclient.KeyResource {
	return MockKeyResource{Error: m.ErrorOnKeys}
}

func (m MockTailnetClient) VIPServices() tsclient.VIPServiceResource {
	return MockVIPServiceResource{Error: m.ErrorOnServices}
}

func (m MockTailnetClient) LoginURL() string {
	return ""
}
