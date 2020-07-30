// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

// SetRoutesFunc applies the given router settings to the OS network stack.
// cfg is guaranteed to be non-nil.
var SetRoutesFunc func(cfg *Config) error

type passthroughRouter struct{}

func (passthroughRouter) Up() error {
	// Bringing up the routes is handled externally.
	return nil
}

func (passthroughRouter) Set(cfg *Config) error {
	if cfg == nil {
		cfg = &shutdownConfig
	}
	return SetRoutesFunc(cfg)
}

func (passthroughRouter) Close() error {
	return SetRoutesFunc(&shutdownConfig)
}

// NewPassthrough returns a Router that passes the received configs to SetRoutesFunc.
func NewPassthrough(logf logger.Logf, _ *device.Device, _ tun.Device) (Router, error) {
	return passthroughRouter{}, nil
}
