// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailnet_test

import (
	"context"
	"io"

	"tailscale.com/internal/client/tailscale"
)

type (
	MockTailnetClient struct {
		ErrorOnDevices  bool
		ErrorOnKeys     bool
		ErrorOnServices bool
	}
)

func (m MockTailnetClient) Devices(_ context.Context, _ *tailscale.DeviceFieldsOpts) ([]*tailscale.Device, error) {
	if m.ErrorOnDevices {
		return nil, io.EOF
	}

	return nil, nil
}

func (m MockTailnetClient) Keys(_ context.Context) ([]string, error) {
	if m.ErrorOnKeys {
		return nil, io.EOF
	}

	return nil, nil
}

func (m MockTailnetClient) ListVIPServices(_ context.Context) (*tailscale.VIPServiceList, error) {
	if m.ErrorOnServices {
		return nil, io.EOF
	}

	return nil, nil
}
