// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !linux && !darwin && !openbsd && !freebsd && !plan9

package router

import (
	"fmt"
	"runtime"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

func newUserspaceRouter(logf logger.Logf, tunDev tun.Device, netMon *netmon.Monitor, health *health.Tracker) (Router, error) {
	return nil, fmt.Errorf("unsupported OS %q", runtime.GOOS)
}

func cleanUp(logf logger.Logf, interfaceName string) {
	// Nothing to do here.
}
