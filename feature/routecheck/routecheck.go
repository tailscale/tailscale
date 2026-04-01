// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package routecheck registers support for RouteCheck,
// which checks the reachability of overlapping routers.
//
// When there are multiple network paths to an IP address, it is being routed by
// overlapping routers. The client uses reachability to pick between those
// paths: either sticking with an active WireGuard session or choosing from the
// peers that it has determined it can reach. It doesn’t need reachability for
// IP addresses that have only one network path, since it can naively attempt to
// establish a WireGuard session.
package routecheck

import (
	"fmt"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/routecheck"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
)

// FeatureName is the name of the feature implemented by this package.
// It is also the [extension] name and the log prefix.
const featureName = "routecheck"

func init() {
	ipnext.RegisterExtension(featureName, func(logf logger.Logf, b ipnext.SafeBackend) (ipnext.Extension, error) {
		return &Extension{
			logf:    logger.WithPrefix(logf, featureName+": "),
			backend: b,
		}, nil
	})
}

// Extension implements the [ipnext.Extension] interface.
type Extension struct {
	Client *routecheck.Client

	logf    logger.Logf
	backend ipnext.SafeBackend
	nb      nodeBackender
	nm      routecheck.NetMapper
}

var _ ipnext.Extension = new(Extension)

// Name implements the [ipnext.Extension.Name] interface method.
func (e *Extension) Name() string {
	return featureName
}

// Init implements the [ipnext.Extension.Init] interface method.
func (e *Extension) Init(h ipnext.Host) error {
	e.nb = nodeBackender{h}

	nm, ok := e.backend.(routecheck.NetMapper)
	if !ok {
		return fmt.Errorf("backend %T does not implement routecheck.NetMapWaiter", e.backend)
	}
	e.nm = nm

	pinger := e.backend.Sys().Engine.Get()

	c, err := routecheck.NewClient(e.logf, e.nb, e.nm, pinger)
	if err != nil {
		return err
	}
	e.Client = c

	h.Hooks().OnNetMapToggle.Add(e.onNetMapToggle)

	return nil
}

// Shutdown implements the [ipnext.Extension.Shutdown] interface method.
func (e *Extension) Shutdown() error {
	return nil
}

func (e *Extension) onNetMapToggle(nm *netmap.NetworkMap) {
	if nm := e.nm.NetMapNoPeers(); nm != nil {
		e.Client.NetMapAvailable(nm)
	}
}
