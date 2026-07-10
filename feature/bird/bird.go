// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package bird integrates Tailscale with the BIRD Internet Routing
// Daemon: it enables the "tailscale" protocol in BIRD while this node
// is a primary subnet router and disables it otherwise. The BIRD
// client implementation lives in tailscale.com/chirp.
package bird

import (
	"net/netip"

	"tailscale.com/chirp"
	"tailscale.com/feature"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/wgengine"
)

func init() {
	feature.Register("bird")
	wgengine.HookNewBird.Set(newBird)
}

// protocolName is the name of the BIRD protocol that Tailscale enables
// while this node is a primary subnet router.
const protocolName = "tailscale"

// bird implements [wgengine.Bird] on top of [chirp.BIRDClient],
// tracking the primary subnet router state across engine
// reconfigurations. One bird exists per engine.
type bird struct {
	logf   logger.Logf
	client *chirp.BIRDClient

	// The fields below are only accessed from Reconfig and
	// ReconfigDone, which the engine serializes under its internal
	// lock.

	// isSubnetRouter is whether the last Reconfig found this node to
	// be a primary subnet router.
	isSubnetRouter bool
	// lastIsSubnetRouter is the primary subnet router state last
	// successfully applied to BIRD. ReconfigDone compares it against
	// isSubnetRouter to decide whether to toggle the protocol.
	lastIsSubnetRouter bool
}

func newBird(logf logger.Logf, socketPath string) (wgengine.Bird, error) {
	logf("wgengine: connecting to BIRD at %s ...", socketPath)
	client, err := chirp.New(socketPath)
	if err != nil {
		return nil, err
	}
	// Disable the protocol at start time; ReconfigDone enables it only
	// once this node becomes a primary subnet router.
	if err := client.DisableProtocol(protocolName); err != nil {
		return nil, err
	}
	return &bird{logf: logf, client: client}, nil
}

func (b *bird) Reconfig(self tailcfg.NodeView) (changed bool) {
	b.isSubnetRouter = false
	if self.Valid() {
		b.isSubnetRouter = hasOverlap(self.PrimaryRoutes(), self.Hostinfo().RoutableIPs())
		b.logf("[v1] Reconfig: hasOverlap(%v, %v) = %v; isSubnetRouter=%v lastIsSubnetRouter=%v",
			self.PrimaryRoutes(), self.Hostinfo().RoutableIPs(),
			b.isSubnetRouter, b.isSubnetRouter, b.lastIsSubnetRouter)
	}
	return b.isSubnetRouter != b.lastIsSubnetRouter
}

func (b *bird) ReconfigDone() {
	if b.isSubnetRouter == b.lastIsSubnetRouter {
		return
	}
	b.logf("wgengine: Reconfig: configuring BIRD")
	var err error
	if b.isSubnetRouter {
		err = b.client.EnableProtocol(protocolName)
	} else {
		err = b.client.DisableProtocol(protocolName)
	}
	if err != nil {
		// Log but don't fail here; a later Reconfig will retry.
		b.logf("wgengine: error configuring BIRD: %v", err)
		return
	}
	b.lastIsSubnetRouter = b.isSubnetRouter
}

func (b *bird) Close() {
	b.client.DisableProtocol(protocolName)
	b.client.Close()
}

// hasOverlap reports whether any prefix in rips is also present in aips.
func hasOverlap(aips, rips views.Slice[netip.Prefix]) bool {
	for _, aip := range aips.All() {
		if views.SliceContains(rips, aip) {
			return true
		}
	}
	return false
}
