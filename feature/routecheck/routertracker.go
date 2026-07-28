// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/net/routecheck"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

var ErrRouteCheckNotEnabled = errors.New("routecheck not enabled")

type RouterTracker struct {
	// OnNetMapAvailable is called when the initial network map is received
	// or is loaded from its cache.
	OnNetMapAvailable func()

	// OnRoutersChange is called when one or more peer nodes, which function as routers,
	// have been added, removed, or change their routes.
	OnRoutersChange func(added, modified, removed []tailcfg.NodeID)

	ctx    context.Context // root context
	logf   logger.Logf
	ipnbus ipnext.NotifyWatcher

	mu     sync.Mutex
	closed bool
	self   tailcfg.NodeView   // self node for the IPN bus being watched
	cancel context.CancelFunc // non-nil iff the watcher is running
	done   chan struct{}      // closed by the watcher goroutine when it exits
}

// TrackRouters returns a tracker for keeping track of which nodes are routers
// by watching the IPN bus for netmap changes.
func TrackRouters(ctx context.Context, logf logger.Logf, ipnbus ipnext.NotifyWatcher) *RouterTracker {
	return &RouterTracker{
		ctx:    ctx,
		logf:   logf,
		ipnbus: ipnbus,
	}
}

// Close implements the [io.Closer] interface.
func (rt *RouterTracker) Close() error {
	if rt == nil {
		return nil
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.closed {
		return nil
	}
	rt.closed = true

	rt.stopWatcherLocked()
	return nil
}

// StartStopWatcher starts or stops watching the IPN bus based on
// the state of the "client-side-reachability-routecheck" node attribute:
// see [tailcfg.NodeAttrClientSideReachabilityRouteCheck].
//
// StartStopWatcher considers stopping and then restarting the watcher goroutine
// if the self node and user differ from the ones that started the current watcher.
// It stops or starts the watcher when routecheck is disabled or enabled, respectively.
//
// StartStopWatcher reports whether the watcher goroutine was started,
// either because it was previously stopped or because it needed restarting.
func (rt *RouterTracker) StartStopWatcher(self tailcfg.NodeView) (started bool, _ error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	orig := rt.self
	rt.self = self

	toggled := routecheck.IsEnabled(orig) != routecheck.IsEnabled(self)
	if toggled || !sameNode(orig, self) {
		rt.stopWatcherLocked()
		if err := rt.startWatcherLocked(self); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// sameNode reports whether a and b have the same [tailcfg.NodeView.ID]s.
func sameNode(a, b tailcfg.NodeView) bool {
	var aID, bID tailcfg.NodeID
	if a.Valid() {
		aID = a.ID()
	}
	if b.Valid() {
		bID = b.ID()
	}
	return aID == bID
}

// startWatcherLocked launches the goroutine that watches the IPN bus.
// rt.mu must be held and the watcher must not already be running.
func (rt *RouterTracker) startWatcherLocked(self tailcfg.NodeView) error {
	syncs.RequiresMutex(&rt.mu)
	if rt.closed {
		return fmt.Errorf("cannot start, tracker was closed")
	}
	if rt.cancel != nil || rt.done != nil {
		return fmt.Errorf("cannot start, already watching IPN bus")
	}

	if !routecheck.IsEnabled(self) {
		if !self.Valid() {
			return ErrRouteCheckNotEnabled
		}
		return fmt.Errorf("%w for %v on %v", ErrRouteCheckNotEnabled, self.User(), self.ID())
	}
	rt.self = self

	ctx, cancel := context.WithCancel(rt.ctx)
	rt.cancel = cancel
	rt.done = make(chan struct{})

	go rt.watchIPNBus(ctx, rt.done, self)
	return nil
}

// stopWatcherLocked cancels the watcher goroutine and waits for it to exit.
// rt.mu must be held. It is a no-op when no watcher is running.
//
// Blocking while locked is safe because the watcher’s callback never locks rt.mu.
func (rt *RouterTracker) stopWatcherLocked() {
	syncs.RequiresMutex(&rt.mu)
	var stopped bool
	if rt.cancel != nil {
		rt.cancel()
		rt.cancel = nil
		stopped = true
	}
	if rt.done != nil {
		<-rt.done
		rt.done = nil
		stopped = true
	}
	rt.self = tailcfg.NodeView{}
	if stopped {
		rt.logf("stopped tracking routers")
	}
}

// watchIPNBus subscribes to the IPN bus to learn about changes to the peer map,
// so that it can keep track of which nodes are routers by dead-reckoning.
// The set of routers is tracked internally to process peer churn without locking.
//
// When routers are added, removed, or change their routes,
// it fires the [RouterTracker.OnRoutersChange] hook.
// See tailscale/tailscale#12542.
//
// When the client gets the initial netmap after connecting to the control plane,
// it fires the [RouterTracker.OnNetMapAvailable] hook.
//
// To avoid stalls, these notifications must be processed promptly
// because we enabled [ipn.NotifyInProcessNoDisconnect] which blocks the caller.
func (rt *RouterTracker) watchIPNBus(ctx context.Context, done chan<- struct{}, self tailcfg.NodeView) {
	defer close(done)

	routers := make(set.Set[tailcfg.NodeID])
	const mask = ipn.NotifyInProcessNoDisconnect | ipn.NotifyInitialStatus | ipn.NotifyPeerChanges
	rt.ipnbus.WatchNotifications(ctx, mask, nil, func(n *ipn.Notify) bool {
		var added, modified, removed []tailcfg.NodeID
		if s := n.InitialStatus; s != nil {
			if rt.OnNetMapAvailable != nil {
				rt.OnNetMapAvailable()
			}
			// Bootstrap the router set from the initial Status.
			// This will trigger the initial probe for all routers.
			for _, ps := range s.Peer {
				if ps.IsRouter() {
					nid := ps.NodeID
					routers.Add(nid)
					added = append(added, nid)
				}
			}
		}
		for _, p := range n.PeersChanged {
			nid := p.ID
			wasRouter := routers.Contains(p.ID)
			isRouter := p.IsRouter()
			switch {
			case !wasRouter && isRouter:
				routers.Add(nid)
				added = append(added, nid)
			case wasRouter && isRouter:
				// TODO(sfllaw): Tune this to ignore changes
				// that don’t affect this node’s status as a router.
				modified = append(modified, nid)
			case wasRouter && !isRouter:
				routers.Delete(nid)
				removed = append(removed, nid)
			}
		}
		for _, nid := range n.PeersRemoved {
			if routers.Contains(nid) {
				routers.Delete(nid)
				removed = append(removed, nid)
			}
		}

		if added != nil || modified != nil || removed != nil {
			if rt.OnRoutersChange != nil {
				rt.OnRoutersChange(added, modified, removed)
			}
		}
		return true
	})
	rt.logf("stopped tracking routers")
}
