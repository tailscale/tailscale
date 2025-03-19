// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package router

import (
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

func newUserspaceRouter(logf logger.Logf, tunDev tun.Device, netMon *netmon.Monitor, health *health.Tracker) (Router, error) {
	// Note, this codepath is _not_ used when building the android app
	// from github.com/tailscale/tailscale-android. The android app
	// constructs its own wgengine with a custom router implementation
	// that plugs into Android networking APIs.
	//
	// In practice, the only place this fake router gets used is when
	// you build a tsnet app for android, in which case we don't want
	// to touch the OS network stack and a no-op router is correct.
	return NewFake(logf), nil
}

func cleanUp(logf logger.Logf, interfaceName string) {
	// Nothing to do here.
}
