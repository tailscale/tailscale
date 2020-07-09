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
	logf    logger.Logf
	tunname string
	Router
}

func newUserspaceRouter(logf logger.Logf, _ *device.Device, tundev tun.Device) (Router, error) {
	tunname, err := tundev.Name()
	if err != nil {
		return nil, err
	}

	userspaceRouter, err := newUserspaceBSDRouter(logf, nil, tundev)
	if err != nil {
		return nil, err
	}

	return &darwinRouter{
		logf:    logf,
		tunname: tunname,
		Router:  userspaceRouter,
	}, nil
}

func (r *darwinRouter) Set(cfg *Config) error {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	if SetRoutesFunc != nil {
		return SetRoutesFunc(cfg)
	}

	return r.Router.Set(cfg)
}

func (r *darwinRouter) Up() error {
	if SetRoutesFunc != nil {
		return nil // bringing up the tunnel is handled externally
	}
	return r.Router.Up()
}

func upDNS(config DNSConfig, interfaceName string) error {
	// Handled by IPNExtension
	return nil
}

func downDNS(interfaceName string) error {
	// Handled by IPNExtension
	return nil
}
