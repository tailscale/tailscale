// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package portmapper registers support for NAT-PMP, PCP, and UPnP port
// mapping protocols to help get direction connections through NATs.
package portmapper

import (
	"context"

	"tailscale.com/feature"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/net/portmapper/portmappertype"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

func init() {
	feature.Register("portmapper")
	portmappertype.HookNewPortMapper.Set(newPortMapper)
}

func newPortMapper(
	ctx context.Context,
	logf logger.Logf,
	bus *eventbus.Bus,
	netMon *netmon.Monitor,
	disableUPnPOrNil func() bool,
	onlyTCP443OrNil func() bool,
) portmappertype.Client {
	pm := portmapper.NewClient(portmapper.Config{
		ShutdownCtx: ctx,
		EventBus:    bus,
		Logf:        logf,
		NetMon:      netMon,
		DebugKnobs: &portmapper.DebugKnobs{
			DisableAll:      onlyTCP443OrNil,
			DisableUPnPFunc: disableUPnPOrNil,
		},
	})
	pm.SetGatewayLookupFunc(netMon.GatewayAndSelfIP)
	return pm
}
