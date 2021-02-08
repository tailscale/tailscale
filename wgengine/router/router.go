// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package router presents an interface to manipulate the host network
// stack's state.
package router

import (
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/types/preftype"
	"tailscale.com/wgengine/router/dns"
)

// Router is responsible for managing the system network stack.
//
// There is typically only one instance of this interface per process.
type Router interface {
	// Up brings the router up.
	Up() error

	// Set updates the OS network stack with a new Config. It may be
	// called multiple times with identical Configs, which the
	// implementation should handle gracefully.
	Set(*Config) error

	// Close closes the router.
	Close() error
}

// New returns a new Router for the current platform, using the
// provided tun device.
func New(logf logger.Logf, wgdev *device.Device, tundev tun.Device) (Router, error) {
	logf = logger.WithPrefix(logf, "router: ")
	return newUserspaceRouter(logf, wgdev, tundev)
}

// Cleanup restores the system network configuration to its original state
// in case the Tailscale daemon terminated without closing the router.
// No other state needs to be instantiated before this runs.
func Cleanup(logf logger.Logf, interfaceName string) {
	mconfig := dns.ManagerConfig{
		Logf:          logf,
		InterfaceName: interfaceName,
		Cleanup:       true,
	}
	dns := dns.NewManager(mconfig)
	if err := dns.Down(); err != nil {
		logf("dns down: %v", err)
	}
	cleanup(logf, interfaceName)
}

// Config is the subset of Tailscale configuration that is relevant to
// the OS's network stack.
type Config struct {
	LocalAddrs []netaddr.IPPrefix
	Routes     []netaddr.IPPrefix // routes to point into the Tailscale interface

	DNS dns.Config

	// Linux-only things below, ignored on other platforms.

	SubnetRoutes     []netaddr.IPPrefix     // subnets being advertised to other Tailscale nodes
	SNATSubnetRoutes bool                   // SNAT traffic to local subnets
	NetfilterMode    preftype.NetfilterMode // how much to manage netfilter rules
}

// shutdownConfig is a routing configuration that removes all router
// state from the OS. It's the config used when callers pass in a nil
// Config.
var shutdownConfig = Config{}
