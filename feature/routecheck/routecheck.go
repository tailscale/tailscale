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
	"sync"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/net/routecheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/set"
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

	logf        logger.Logf
	backend     ipnext.SafeBackend
	watcher     ipnext.NotifyWatcher
	eventClient *eventbus.Client
	nb          nodeBackender
	nm          routecheck.NetMapper

	mu          sync.Mutex
	cancelWatch context.CancelFunc // non-nil iff the IPN bus watcher is running
	watchDone   chan struct{}      // closed by the watcher goroutine when it exits
	watchSelf   selfNodeKey        // identity of self the running watcher was started for
	shutdown    bool
}

// selfNodeKey identifies a self node for the purpose of detecting profile
// switches. It mirrors the producer-side identity used in
// [ipnlocal.sameSelfNode].
type selfNodeKey struct {
	id       tailcfg.NodeID
	stableID tailcfg.StableNodeID
	user     tailcfg.UserID
}

func selfKeyOf(self tailcfg.NodeView) selfNodeKey {
	if !self.Valid() {
		return selfNodeKey{}
	}
	return selfNodeKey{
		id:       self.ID(),
		stableID: self.StableID(),
		user:     self.User(),
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

	watcher, ok := e.backend.(ipnext.NotifyWatcher)
	if !ok {
		return fmt.Errorf("backend %T does not implement ipnext.NotifyWatcher", e.backend)
	}
	e.watcher = watcher

	pinger := e.backend.Sys().Engine.Get()

	logf := logger.WithPrefix(e.logf, "routecheck: ")
	c, err := routecheck.NewClient(logf, e.nb, e.nm, pinger)
	if err != nil {
		return err
	}
	e.Client = c

	bus := e.backend.Sys().Bus.Get()
	e.eventClient = bus.Client("routecheck")
	eventbus.SubscribeFunc(e.eventClient, e.onNetMonChange)

	h.Hooks().OnSelfChange.Add(e.onSelfChange)

	// Catch the case where self is already valid (e.g., from a cached
	// netmap) at extension Init time: OnSelfChange would not fire later
	// for that pre-existing state.
	e.syncWatchSubscription(e.nb.NodeBackend().Self())

	go func() {
		if err := e.Client.Start(context.Background()); err != nil {
			logf("background client failed: %v", err)
		}
	}()
	return nil
}

// Shutdown implements the [ipnext.Extension.Shutdown] interface method.
func (e *Extension) Shutdown() error {
	e.mu.Lock()
	e.shutdown = true
	e.stopWatcherLocked()
	e.mu.Unlock()
	e.eventClient.Close()
	return e.Client.Close()
}

// onSelfChange runs when the LocalBackend's self node changes (including
// when its capabilities change), so we can start or stop the IPN bus
// watcher in response to the routecheck node attributes being toggled
// on or off for this tailnet.
func (e *Extension) onSelfChange(self tailcfg.NodeView) {
	e.syncWatchSubscription(self)
}

// syncWatchSubscription starts the IPN bus watcher when routecheck is
// enabled for self and stops it when it is not. It also restarts the
// watcher when the self node's identity changes (e.g., a profile
// switch) so the new watcher rebootstraps its router set from a fresh
// InitialStatus, instead of carrying stale NodeIDs from the previous
// account.
//
// It is safe to call from any goroutine.
func (e *Extension) syncWatchSubscription(self tailcfg.NodeView) {
	enabled := routecheck.IsEnabled(self)
	key := selfKeyOf(self)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.shutdown {
		return
	}
	running := e.cancelWatch != nil
	switch {
	case enabled && !running:
		e.startWatcherLocked(key)
	case !enabled && running:
		e.stopWatcherLocked()
	case enabled && running && key != e.watchSelf:
		// Profile switch (or other self-node identity change).
		// Restart so the bootstrap from InitialStatus replaces the
		// router set in full.
		e.stopWatcherLocked()
		e.startWatcherLocked(key)
	}
}

// startWatcherLocked launches the IPN bus watcher goroutine.
// e.mu must be held and the watcher must not already be running.
func (e *Extension) startWatcherLocked(key selfNodeKey) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	e.cancelWatch = cancel
	e.watchDone = done
	e.watchSelf = key
	go e.watchIPNBus(ctx, done)
}

// stopWatcherLocked cancels the watcher goroutine and waits for it to
// exit. e.mu must be held. It is a no-op when no watcher is running.
//
// Blocking under e.mu is safe because the watcher's callback never
// acquires e.mu.
func (e *Extension) stopWatcherLocked() {
	if e.cancelWatch == nil {
		return
	}
	e.cancelWatch()
	<-e.watchDone
	e.cancelWatch = nil
	e.watchDone = nil
	e.watchSelf = selfNodeKey{}
}

// watchIPNBus subscribes to the IPN bus to learn about peer additions,
// removals, and modifications, computes whether the set of routers among
// those peers has changed, and signals the [routecheck.Client] to refresh
// when it has.
//
// It tracks the set of router peer IDs internally instead of relying on a
// LocalBackend hook so that peer churn is processed via the existing
// constant-time delta path. See tailscale/tailscale#12542.
func (e *Extension) watchIPNBus(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	routers := make(set.Set[tailcfg.NodeID])
	const mask = ipn.NotifyInitialStatus | ipn.NotifyPeerChanges
	e.watcher.WatchNotifications(ctx, mask, nil, func(n *ipn.Notify) bool {
		refresh := false
		if s := n.InitialStatus; s != nil {
			// Bootstrap the router set from the initial Status. This
			// is the modern, scalable replacement for reading peers
			// off [ipn.Notify.NetMap] under NotifyInitialNetMap.
			if nm := e.nm.NetMapNoPeers(); nm != nil {
				e.Client.NotifyNetMapAvailable(nm)
			}
			for _, ps := range s.Peer {
				if peerStatusIsRouter(ps) {
					if !routers.Contains(ps.NodeID) {
						routers.Add(ps.NodeID)
						refresh = true
					}
				}
			}
		}
		for _, p := range n.PeersChanged {
			isRouter := p.IsRouter()
			wasRouter := routers.Contains(p.ID)
			switch {
			case isRouter && !wasRouter:
				routers.Add(p.ID)
				refresh = true
			case !isRouter && wasRouter:
				routers.Delete(p.ID)
				refresh = true
			case isRouter && wasRouter:
				// A known router was modified; routes or other
				// reachability-relevant fields may have changed.
				refresh = true
			}
		}
		for _, id := range n.PeersRemoved {
			if routers.Contains(id) {
				routers.Delete(id)
				refresh = true
			}
		}
		if n.SelfChange != nil {
			refresh = true
		}
		if refresh {
			e.needsRefresh()
		}
		return true
	})
}

// peerStatusIsRouter reports whether ps describes a peer that routes
// addresses beyond its own. It is the [ipnstate.PeerStatus] analogue of
// [tailcfg.Node.IsRouter]: TailscaleIPs are the peer's own host
// addresses and AllowedIPs is a superset that also includes any subnet
// routes or exit routes the peer advertises, so the peer is a router
// when AllowedIPs has more entries than TailscaleIPs.
func peerStatusIsRouter(ps *ipnstate.PeerStatus) bool {
	if ps == nil || ps.AllowedIPs == nil {
		return false
	}
	return ps.AllowedIPs.Len() > len(ps.TailscaleIPs)
}

func (e *Extension) onNetMonChange(delta netmon.ChangeDelta) {
	if delta.RebindLikelyRequired {
		e.needsRefresh()
	}
}

func (e *Extension) needsRefresh() {
	if !routecheck.IsEnabled(e.nb.NodeBackend().Self()) {
		return
	}
	e.Client.NeedsRefresh()
}
