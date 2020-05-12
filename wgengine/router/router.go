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
	return newUserspaceRouter(logf, wgdev, tundev)
}

// Config is the subset of Tailscale configuration that is relevant to
// the OS's network stack.
type Config struct {
	LocalAddrs   []netaddr.IPPrefix
	DNS          []netaddr.IP
	DNSDomains   []string
	Routes       []netaddr.IPPrefix // routes to point into the Tailscale interface
	SubnetRoutes []netaddr.IPPrefix // subnets being advertised to other Tailscale nodes
	NoSNAT       bool               // don't SNAT traffic to local subnets
}

// shutdownConfig is a routing configuration that removes all router
// state from the OS. It's the config used when callers pass in a nil
// Config.
var shutdownConfig = Config{
	// TODO(danderson): set more things in here to disable all
	// firewall rules and routing overrides when nil.
	NoSNAT: true,
}
