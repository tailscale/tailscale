// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/routecheck"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/set"
)

var routecheckNotEnabledErr = errors.New("routecheck not enabled")

type RouterTracker struct {
	// OnNetMapAvailable is called (with RouteTracker.mu held)
	// when the initial network map is received or loaded from its cache.
	OnNetMapAvailable func()

	// OnRoutersChange is called (with RouteTracker.mu held)
	// when one or more peer nodes, which function as routers,
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

// TrackRouters returns a tracker that watches the IPN bus for netmap changes
// to keep track of which nodes are routers.
// It returns nil if routecheck is not enabled for self.
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

// OnSelfChange runs when the LocalBackend’s self node changes,
// so the tracker can start or stop watching the IPN bus
// when the "client-side-reachability:routecheck" node attribute is toggled:
// see [tailcfg.NodeAttrClientSideReachabilityRouteCheck].
func (rt *RouterTracker) OnSelfChange(self tailcfg.NodeView) {
	if _, _, err := rt.maybeRestartWatcher(self); err != nil {
		if !errors.Is(err, routecheckNotEnabledErr) {
			rt.logf("error tracking routers: %v", err)
		}
	}
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
			return routecheckNotEnabledErr
		}
		return fmt.Errorf("%w for %v on %v", routecheckNotEnabledErr, self.User(), self.ID())
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
	if rt.cancel != nil {
		rt.cancel()
		rt.cancel = nil
	}
	if rt.done != nil {
		<-rt.done
		rt.done = nil
	}
	rt.self = tailcfg.NodeView{}
	rt.logf("stopped tracking routers")
}

// maybeRestartWatcher stops and then restarts the watcher goroutine
// if the self node and user differ from the ones that started the current watcher.
// It stops or starts the watcher when routecheck is disabled or enabled, respectively.
// It reports whether the watcher goroutine was both restarted and is also running.
func (rt *RouterTracker) maybeRestartWatcher(self tailcfg.NodeView) (restarted, running bool, err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	orig := rt.self
	rt.self = self

	if !ipnlocal.SameSelfNodeAndUser(orig, self) || routecheck.IsEnabled(orig) != routecheck.IsEnabled(self) {
		restarted = true
		rt.stopWatcherLocked()
		err = rt.startWatcherLocked(self)
	}
	running = rt.cancel != nil
	return restarted, running, err
}

// watchIPNBus subscribes to the IPN bus to learn about changes to the peer map,
// so that it can keep track of which nodes are routers by dead-reckoning.
// The set of routers is tracked internally to process peer churn without locking.
//
// When routers are added, removed, or change their routes,
// It fires the [RouterTracker.OnRoutersChange] hooks
// which must process this notification promptly to avoid stalls.
// See tailscale/tailscale#12542.
func (rt *RouterTracker) watchIPNBus(ctx context.Context, done chan<- struct{}, self tailcfg.NodeView) {
	defer close(done)

	routers := make(set.Set[tailcfg.NodeID])
	var endpoints views.Slice[netip.AddrPort]
	if self.Valid() {
		endpoints = self.Endpoints()
	}

	const mask = ipn.NotifyInProcessNoDisconnect | ipn.NotifyInitialStatus | ipn.NotifyPeerChanges
	rt.ipnbus.WatchNotifications(ctx, mask, nil, func(n *ipn.Notify) bool {
		var added, modified, removed []tailcfg.NodeID
		if s := n.InitialStatus; s != nil {
			if rt.OnNetMapAvailable != nil {
				rt.OnNetMapAvailable()
			}
			// Bootstrap the router set from the initial Status.
			for _, ps := range s.Peer {
				if peerStatusIsRouter(ps) {
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

		if n.SelfChange != nil {
			eps := views.SliceOf(n.SelfChange.Endpoints)
			if !views.SliceEqual(endpoints, eps) {
				// Mark all existing routers as modified
				// because the client’s endpoints have changed.
				modset := routers.Clone()
				modset.DeleteSlice(added)
				modified = modset.Slice()
			}
			endpoints = eps
		}

		if added != nil || modified != nil || removed != nil {
			if rt.OnRoutersChange != nil {
				rt.OnRoutersChange(added, modified, removed)
			}
		}
		return true
	})
	rt.logf("started tracking routers")
}

// peerStatusIsRouter reports whether the peer routes addresses besides its own.
// It is the [ipnstate.PeerStatus] analogue of [tailcfg.Node.IsRouter].
//
// TODO(sfllaw): Write a test that to assert that peerStatusIsRouter and
// Node.IsRouter behave the same.
func peerStatusIsRouter(ps *ipnstate.PeerStatus) bool {
	if ps == nil || ps.AllowedIPs == nil {
		return false
	}
	return ps.AllowedIPs.Len() > len(ps.TailscaleIPs)
}
