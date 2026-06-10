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
	"errors"
	"fmt"
	"sync"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/net/routecheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
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
	routers *RouterTracker

	reconcile struct {
		sync.Mutex
		args   chan tailcfg.NodeView // pending arguments for StartStopWatcher
		closed bool
		done   chan struct{}
	}
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

	pinger := e.backend.Sys().Engine.Get()

	c, err := routecheck.NewClient(e.logf, e.nb, e.nm, pinger)
	if err != nil {
		return err
	}
	e.Client = c

	e.routers = TrackRouters(context.Background(), e.logf, ipnbus)
	e.routers.OnNetMapAvailable = e.Client.NotifyNetMapAvailable
	e.routers.OnRoutersChange = e.incrementalRefresh

	// Watch for changes to the self node that would toggle the routecheck feature.
	e.reconcile.args = make(chan tailcfg.NodeView, 1)
	e.reconcile.done = make(chan struct{})
	go e.reconcileLoop()
	h.Hooks().OnSelfChange.Add(e.reconcileWatcher)

	return nil
}

// Shutdown implements the [ipnext.Extension.Shutdown] interface method.
func (e *Extension) Shutdown() error {
	e.reconcile.Lock()
	e.reconcile.closed = true
	close(e.reconcile.args) // lock prevents reconcileWatcher from writing to this channel
	e.reconcile.Unlock()

	e.routers.Close() // stop the watcher before waiting for reconcile.done
	<-e.reconcile.done
	return e.Client.Close()
}

func (e *Extension) needsRefresh() {
	// TODO(sfllaw): Call e.Client.NeedsRefresh() after implementing it.
}

func (e *Extension) incrementalRefresh(added, modified, removed []tailcfg.NodeID) {
	// TODO(sfllaw): This refresh should be incremental,
	// based on the added, modified, and removed nodes.
	// Currently it refreshes everything.
	e.needsRefresh()
}

// reconcileWatcher is called whenever e.routers should start, stop, or restart its watcher.
// It may trigger a restart when self indicates that we have switched to a different tailnet or user,
// in order to reset the internal state of e.routers and start tracking from scratch.
// This work is performed by [Extension.reconcileLoop].
//
// This function must never block, because it’s called from
// [ipnlocal.LocalBackend.SetControlClientStatus], which locks LocalBackend.mu.
// This lock is also acquired when unwinding [ipnlocal.LocalBackend.WatchNotificationsAs]
// which is what [RouterTracker.stopWatcherLocked] is waiting for.
func (e *Extension) reconcileWatcher(self tailcfg.NodeView) {
	e.reconcile.Lock()
	defer e.reconcile.Unlock()
	if e.reconcile.closed {
		return
	}
	select {
	case <-e.reconcile.args: // drain stale args so StartStopWatcher is always called with the latest
	default:
	}
	e.reconcile.args <- self
}

// reconcileLoop starts, stops, or restarts its watcher after calls to [Extension.reconcileWatcher].
func (e *Extension) reconcileLoop() {
	defer close(e.reconcile.done)
	for self := range e.reconcile.args {
		started, err := e.routers.StartStopWatcher(self)
		if err != nil {
			if !errors.Is(err, ErrRouteCheckNotEnabled) {
				e.logf("error tracking routers: %v", err)
			}
			continue // can be started by toggling the nodeattr
		}
		if started {
			e.needsRefresh()
		}
	}
}
