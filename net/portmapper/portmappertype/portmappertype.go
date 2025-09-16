// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package portmappertype defines the net/portmapper interface, which may or may not be
// linked into the binary.
package portmappertype

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"tailscale.com/feature"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

// HookNewPortMapper is a hook to install the portmapper creation function.
// It must be set by an init function when buildfeatures.HasPortmapper is true.
var HookNewPortMapper feature.Hook[func(logf logger.Logf,
	bus *eventbus.Bus,
	netMon *netmon.Monitor,
	disableUPnPOrNil,
	onlyTCP443OrNil func() bool) Client]

var (
	ErrNoPortMappingServices = errors.New("no port mapping services were found")
	ErrGatewayRange          = errors.New("skipping portmap; gateway range likely lacks support")
	ErrGatewayIPv6           = errors.New("skipping portmap; no IPv6 support for portmapping")
	ErrPortMappingDisabled   = errors.New("port mapping is disabled")
)

// ProbeResult is the result of a portmapper probe, saying
// which port mapping protocols were discovered.
type ProbeResult struct {
	PCP  bool
	PMP  bool
	UPnP bool
}

// Client is the interface implemented by a portmapper client.
type Client interface {
	// Probe returns a summary of which port mapping services are available on
	// the network.
	//
	// If a probe has run recently and there haven't been any network changes
	// since, the returned result might be server from the Client's cache,
	// without sending any network traffic.
	Probe(context.Context) (ProbeResult, error)

	// HaveMapping reports whether we have a current valid mapping.
	HaveMapping() bool

	// SetGatewayLookupFunc set the func that returns the machine's default
	// gateway IP, and the primary IP address for that gateway. It must be
	// called before the client is used. If not called,
	// interfaces.LikelyHomeRouterIP is used.
	SetGatewayLookupFunc(f func() (gw, myIP netip.Addr, ok bool))

	// NoteNetworkDown should be called when the network has transitioned to a down state.
	// It's too late to release port mappings at this point (the user might've just turned off
	// their wifi), but we can make sure we invalidate mappings for later when the network
	// comes back.
	NoteNetworkDown()

	// GetCachedMappingOrStartCreatingOne quickly returns with our current cached portmapping, if any.
	// If there's not one, it starts up a background goroutine to create one.
	// If the background goroutine ends up creating one, the onChange hook registered with the
	// NewClient constructor (if any) will fire.
	GetCachedMappingOrStartCreatingOne() (external netip.AddrPort, ok bool)

	// SetLocalPort updates the local port number to which we want to port
	// map UDP traffic
	SetLocalPort(localPort uint16)

	Close() error
}

// Mapping is an event recording the allocation of a port mapping.
type Mapping struct {
	External  netip.AddrPort
	Type      string
	GoodUntil time.Time

	// TODO(creachadair): Record whether we reused an existing mapping?
}
