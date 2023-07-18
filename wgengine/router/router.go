// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package router presents an interface to manipulate the host network
// stack's state.
package router

import (
	"net/netip"
	"reflect"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/netmon"
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
//
// If netMon is nil, it's not used. It's currently (2021-07-20) only
// used on Linux in some situations.
func New(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor) (Router, error) {
	logf = logger.WithPrefix(logf, "router: ")
	return newUserspaceRouter(logf, tundev, netMon)
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
	LocalAddrs []netip.Prefix

	// Routes are the routes that point into the Tailscale
	// interface.  These are the /32 and /128 routes to peers, as
	// well as any other subnets that peers are advertising and
	// this node has chosen to use.
	Routes []netip.Prefix

	// LocalRoutes are the routes that should not be routed through Tailscale.
	// There are no priorities set in how these routes are added, normal
	// routing rules apply.
	LocalRoutes []netip.Prefix

	// NewMTU is currently only used by the MacOS network extension
	// app to set the MTU of the tun in the router configuration
	// callback. If zero, the MTU is unchanged.
	NewMTU int

	// Linux-only things below, ignored on other platforms.
	SubnetRoutes     []netip.Prefix         // subnets being advertised to other Tailscale nodes
	SNATSubnetRoutes bool                   // SNAT traffic to local subnets
	NetfilterMode    preftype.NetfilterMode // how much to manage netfilter rules
}

func (a *Config) Equal(b *Config) bool {
	if a == nil && b == nil {
		return true
	}
	if (a == nil) != (b == nil) {
		return false
	}
	return reflect.DeepEqual(a, b)
}

// shutdownConfig is a routing configuration that removes all router
// state from the OS. It's the config used when callers pass in a nil
// Config.
var shutdownConfig = Config{}
