// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

func newUserspaceRouter(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor, health *health.Tracker, bus *eventbus.Bus) (Router, error) {
	return newUserspaceBSDRouter(logf, tundev, netMon, health)
}

func cleanUp(logger.Logf, string) {
	// Nothing to do.
}
