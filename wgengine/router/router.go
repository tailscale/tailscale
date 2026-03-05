// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package router presents an interface to manipulate the host network
// stack's state.
package router

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"slices"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/types/preftype"
	"tailscale.com/util/eventbus"
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

// NewOpts are the options passed to the NewUserspaceRouter hook.
type NewOpts struct {
	Logf   logger.Logf     // required
	Tun    tun.Device      // required
	NetMon *netmon.Monitor // optional
	Health *health.Tracker // required (but TODO: support optional later)
	Bus    *eventbus.Bus   // required
}

// PortUpdate is an eventbus value, reporting the port and address family
// magicsock is currently listening on, so it can be threaded through firewalls
// and such.
type PortUpdate struct {
	UDPPort         uint16
	EndpointNetwork string // either "udp4" or "udp6".
}

// HookNewUserspaceRouter is the registration point for router implementations
// to register a constructor for userspace routers. It's meant for implementations
// in wgengine/router/osrouter.
//
// If no implementation is registered, [New] will return an error.
var HookNewUserspaceRouter feature.Hook[func(NewOpts) (Router, error)]

// New returns a new Router for the current platform, using the
// provided tun device.
//
// If netMon is nil, it's not used. It's currently (2021-07-20) only
// used on Linux in some situations.
func New(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor,
	health *health.Tracker, bus *eventbus.Bus,
) (Router, error) {
	logf = logger.WithPrefix(logf, "router: ")
	if f, ok := HookNewUserspaceRouter.GetOk(); ok {
		return f(NewOpts{
			Logf:   logf,
			Tun:    tundev,
			NetMon: netMon,
			Health: health,
			Bus:    bus,
		})
	}
	if !buildfeatures.HasOSRouter {
		return nil, errors.New("router: tailscaled was built without OSRouter support")
	}
	return nil, fmt.Errorf("unsupported OS %q", runtime.GOOS)
}

// HookCleanUp is the optional registration point for router implementations
// to register a cleanup function for [CleanUp] to use. It's meant for
// implementations in wgengine/router/osrouter.
var HookCleanUp feature.Hook[func(_ logger.Logf, _ *netmon.Monitor, ifName string)]

// CleanUp restores the system network configuration to its original state
// in case the Tailscale daemon terminated without closing the router.
// No other state needs to be instantiated before this runs.
func CleanUp(logf logger.Logf, netMon *netmon.Monitor, interfaceName string) {
	if f, ok := HookCleanUp.GetOk(); ok {
		f(logf, netMon, interfaceName)
	}
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

	// SubnetRoutes is the list of subnets that this node is
	// advertising to other Tailscale nodes.
	// As of 2023-10-11, this field is only used for network
	// flow logging and is otherwise ignored.
	SubnetRoutes []netip.Prefix

	// Linux-only things below, ignored on other platforms.
	SNATSubnetRoutes  bool                   // SNAT traffic to local subnets
	StatefulFiltering bool                   // Apply stateful filtering to inbound connections
	NetfilterMode     preftype.NetfilterMode // how much to manage netfilter rules
	NetfilterKind     string                 // what kind of netfilter to use ("nftables", "iptables", or "" to auto-detect)

	// LinuxPacketMarks contains the packet mark values to use for Linux
	// firewall rules and routing. If nil, defaults from tsconst are used.
	// Only used on Linux.
	LinuxPacketMarks *LinuxPacketMarks
}

// LinuxPacketMarks holds the packet mark configuration for Linux.
// This is a copy of ipn.LinuxPacketMarks to avoid circular imports.
type LinuxPacketMarks struct {
	FwmarkMask      uint32
	SubnetRouteMark uint32
	BypassMark      uint32
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

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	c2 := *c
	c2.LocalAddrs = slices.Clone(c.LocalAddrs)
	c2.Routes = slices.Clone(c.Routes)
	c2.LocalRoutes = slices.Clone(c.LocalRoutes)
	c2.SubnetRoutes = slices.Clone(c.SubnetRoutes)
	return &c2
}
