// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package router presents an interface to manipulate the host network
// stack's state.
package router

import (
	"github.com/tailscale/wireguard-go/tun"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/types/preftype"
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
func New(logf logger.Logf, tundev tun.Device) (Router, error) {
	logf = logger.WithPrefix(logf, "router: ")
	return newUserspaceRouter(logf, tundev)
}

// Cleanup restores the system network configuration to its original state
// in case the Tailscale daemon terminated without closing the router.
// No other state needs to be instantiated before this runs.
func Cleanup(logf logger.Logf, interfaceName string) {
	cleanup(logf, interfaceName)
}

// Config is the subset of Tailscale configuration that is relevant to
// the OS's network stack.
type Config struct {
	// LocalAddrs are the address(es) for this node. This is
	// typically one IPv4/32 (the 100.x.y.z CGNAT) and one
	// IPv6/128 (Tailscale ULA).
	LocalAddrs []netaddr.IPPrefix

	// Routes are the routes that point in to the Tailscale
	// interface.  These are the /32 and /128 routes to peers, as
	// well as any other subnets that peers are advertising and
	// this node has chosen to use.
	Routes []netaddr.IPPrefix

	// Linux-only things below, ignored on other platforms.
	SubnetRoutes     []netaddr.IPPrefix     // subnets being advertised to other Tailscale nodes
	SNATSubnetRoutes bool                   // SNAT traffic to local subnets
	NetfilterMode    preftype.NetfilterMode // how much to manage netfilter rules
}

// shutdownConfig is a routing configuration that removes all router
// state from the OS. It's the config used when callers pass in a nil
// Config.
var shutdownConfig = Config{}
