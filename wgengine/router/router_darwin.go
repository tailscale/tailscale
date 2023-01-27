// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package router

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/monitor"
)

func newUserspaceRouter(logf logger.Logf, tundev tun.Device, linkMon *monitor.Mon) (Router, error) {
	return newUserspaceBSDRouter(logf, tundev, linkMon)
}

func cleanup(logger.Logf, string) {
	// Nothing to do.
}
