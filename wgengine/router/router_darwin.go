// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

type darwinRouter struct {
	tunname string
}

func newUserspaceRouter(logf logger.Logf, _ *device.Device, tundev tun.Device) (Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}
	return &darwinRouter{tunname: tunname}, nil
}

func (r *darwinRouter) Up() error {
	return nil
}

func (r *darwinRouter) Set(cfg *Config) error {
	if SetRoutesFunc == nil {
		return nil
	}
	if cfg == nil {
		cfg = &shutdownConfig
	}
	return SetRoutesFunc(cfg)
}

func (r *darwinRouter) Close() error {
	return nil
}
