// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

func newUserspaceRouter(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor) (Router, error) {
	return newUserspaceBSDRouter(logf, tundev, netMon)
}

func cleanUp(logger.Logf, string) {
	// Nothing to do.
}
