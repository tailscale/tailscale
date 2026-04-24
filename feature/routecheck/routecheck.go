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
	"context"
	"fmt"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/netmon"
	"tailscale.com/net/routecheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
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

	ipnlocal.HookRouteCheckReport.Set(routeCheckReport)
}

// Extension implements the [ipnext.Extension] interface.
type Extension struct {
	Client *routecheck.Client

	logf    logger.Logf
	backend ipnext.SafeBackend
	ec      *eventbus.Client
	nb      nodeBackender
	nm      routecheck.NetMapper
	routers *RouterTracker
}

var _ ipnext.Extension = new(Extension)

// Name implements the [ipnext.Extension.Name] interface method.
func (e *Extension) Name() string {
	return featureName
}

// Init implements the [ipnext.Extension.Init] interface method.
func (e *Extension) Init(h ipnext.Host) error {
	if routecheck.DebugForceClientSideReachabilityRoutecheck().EqualBool(false) {
		return ipnext.SkipExtension
	}

	ctx := context.Background()
	logf := logger.WithPrefix(e.logf, "routecheck: ")

	e.nb = nodeBackender{h}

	nm, ok := e.backend.(routecheck.NetMapper)
	if !ok {
		return fmt.Errorf("backend %T does not implement routecheck.NetMapper", e.backend)
	}
	e.nm = nm

	ipnbus, ok := e.backend.(ipnext.NotifyWatcher)
	if !ok {
		return fmt.Errorf("backend %T does not implement ipnext.NotifyWatcher", e.backend)
	}
	e.routers = TrackRouters(ctx, logf, ipnbus)
	e.routers.OnNetMapAvailable = e.onNetMapAvailable
	e.routers.OnRoutersChange = e.onRoutersChange

	pinger := e.backend.Sys().Engine.Get()

	c, err := routecheck.NewClient(logf, e.nb, e.nm, pinger)
	if err != nil {
		return err
	}
	e.Client = c

	bus := e.backend.Sys().Bus.Get()
	e.ec = bus.Client("routecheck")
	eventbus.SubscribeFunc(e.ec, e.onNetMonChange)

	h.Hooks().OnSelfChange.Add(e.onSelfChange)
	// Unlike a cold start, starting with a cached netmap
	// may have pre-loaded a valid NodeBackend.Self,
	// so an initial OnSelfChange won’t fire and we have to do it ourselves.
	e.onSelfChange(e.nb.NodeBackend().Self())

	go func() {
		if err := e.Client.Start(context.Background()); err != nil {
			logf("background client failed: %v", err)
		}
	}()
	return nil
}

// Shutdown implements the [ipnext.Extension.Shutdown] interface method.
func (e *Extension) Shutdown() error {
	e.routers.Close()
	e.ec.Close()
	return e.Client.Close()
}

func (e *Extension) needsRefresh() {
	if !routecheck.IsEnabled(e.nb.NodeBackend().Self()) {
		return
	}
	e.Client.NeedsRefresh()
}

func (e *Extension) onNetMapAvailable() {
	e.Client.NotifyNetMapAvailable(e.nm.NetMapNoPeers())
}

func (e *Extension) onNetMonChange(delta netmon.ChangeDelta) {
	if delta.RebindLikelyRequired {
		e.needsRefresh()
	}
}

func (e *Extension) onRoutersChange(added, modified, removed []tailcfg.NodeID) {
	// TODO(sfllaw): This refresh could be incremental,
	// based on the added, modified, and removed nodes.
	e.needsRefresh()
}

func (e *Extension) onSelfChange(self tailcfg.NodeView) {
	e.routers.OnSelfChange(self)
	e.needsRefresh()
}

func routeCheckReport(b *ipnlocal.LocalBackend) ipnlocal.RouteCheckReport {
	c := ClientFor(b)
	if c == nil {
		return nil
	}
	return c.Report()
}
