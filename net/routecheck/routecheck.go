// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package routecheck performs status checks for routes from the current host.
package routecheck

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
)

var (
	metricNeedsRefresh = clientmetric.NewCounter("routecheck_needs_refresh")
	metricRefresh      = clientmetric.NewCounter("routecheck_refresh")
)

// DebugForceClientSideReachabilityRoutecheck reports whether routecheck should be forced on or off.
// If the TS_DEBUG_FORCE_CLIENT_SIDE_REACHABILITY_ROUTECHECK environment variable is true,
// then routecheck is forced on. If it is false, then routecheck is forced off.
// If unset, then the client respects the client-side-reachability and
// client-side-reachability-routecheck node attributes.
var DebugForceClientSideReachabilityRoutecheck = envknob.RegisterOptBool("TS_DEBUG_FORCE_CLIENT_SIDE_REACHABILITY_ROUTECHECK")

// IsEnabled reports whether routecheck probing has been enabled for this client.
func IsEnabled(self tailcfg.NodeView) bool {
	if v, ok := DebugForceClientSideReachabilityRoutecheck().Get(); ok {
		return v // forced
	}
	if !self.Valid() {
		return false
	}
	// TODO(sfllaw): We intend to eventually enable this behaviour by default.
	return self.HasCap(tailcfg.NodeAttrClientSideReachability) &&
		self.HasCap(tailcfg.NodeAttrClientSideReachabilityRouteCheck)
}

// Client generates Reports describing the result of both passive and active
// reachability probing.
type Client struct {
	// Verbose enables verbose logging.
	Verbose bool

	// Logf optionally specifies where to log to.
	// If nil, log.Printf is used.
	Logf logger.Logf

	// These elements are read-only after initialization.
	nb     NodeBackender
	nm     NetMapper
	pinger Pinger
	ctx    context.Context
	cancel context.CancelFunc

	// needsRefresh is sent a message by [Client.NeedsRefresh]
	// to signal that a new report is needed.
	// This message is received by the goroutine spawned by [Client.Start]
	// which probes the appropriate routers to compile a new [Client.report].
	// This channel doesn’t need to be closed because the goroutine is canceled by ctx.
	needsRefresh chan struct{}
	report       atomic.Pointer[Report] // needsRefresh signals that this needs refreshing

	// HasNetMap is a channel that can be closed to wake up goroutines
	// waiting for the netmap received after connecting to the control plane.
	// This channel gets swapped out for a new one whenever it is closed,
	// to handle disconnecting and reconnecting to the control plane.
	hasNetMap atomic.Pointer[chan struct{}]
}

// NetMapper is the interface that returns the current [netmap.NetworkMap].
type NetMapper interface {
	// NetMapNoPeers returns the latest cached network map received from
	// controlclient WITHOUT a freshly-built Peers slice.
	//
	// On a tailnet with frequent peer churn the cached netmap's Peers slice
	// can be stale relative to the live per-node-backend peers map; non-Peers
	// fields (SelfNode, DNS, PacketFilter, capabilities, ...) are always
	// current. Use this for any caller that does not need to iterate Peers,
	// since it's O(1) regardless of tailnet size.
	//
	// Returns nil if no network map has been received yet.
	NetMapNoPeers() *netmap.NetworkMap

	// NetMapWithPeers returns the latest network map with the Peers slice
	// populated.
	//
	// Currently this is the same as [LocalBackend.NetMapNoPeers]: the cached
	// netmap's Peers slice may be stale relative to the live per-node-backend
	// peers map. A follow-up change will switch this method to return a
	// freshly-built netmap with up-to-date Peers, at O(N) cost per call.
	// Callers that genuinely need the up-to-date peer set should use this
	// method (and document why) so the upcoming change reaches them.
	//
	// Returns nil if no network map has been received yet.
	NetMapWithPeers() *netmap.NetworkMap
}

// NodeBackender is the interface that returns the current [NodeBackend].
type NodeBackender interface {
	NodeBackend() NodeBackend
}

// NodeBackend is an interface to query the current node and its peers.
//
// It is not a snapshot in time but is locked to a particular node.
type NodeBackend interface {
	// Self returns the current node.
	Self() tailcfg.NodeView

	// Peers returns all the current peers.
	Peers() []tailcfg.NodeView
}

// Pinger is the interface that wraps the [tailscale.com/ipn/ipnlocal.LocalBackend.Ping] method.
type Pinger interface {
	Ping(ip netip.Addr, pingType tailcfg.PingType, size int, cb func(*ipnstate.PingResult))
}

// NewClient returns a client that probes its peers using this LocalBackend.
func NewClient(ctx context.Context, logf logger.Logf, nb NodeBackender, nm NetMapper, pinger Pinger) (*Client, error) {
	if nb == nil {
		return nil, errors.New("NodeBackender must be set")
	}
	if nm == nil {
		return nil, errors.New("NetMapper must be set")
	}
	if pinger == nil {
		return nil, errors.New("Pinger must be set")
	}

	ctx, cancel := context.WithCancel(ctx)
	c := &Client{
		Logf:   logf,
		nb:     nb,
		nm:     nm,
		pinger: pinger,
		ctx:    ctx,
		cancel: cancel,

		needsRefresh: make(chan struct{}, 1), // debounce using buffer of 1
	}
	c.hasNetMap.Store(new(make(chan struct{})))
	return c, nil
}

// NotifyNetMapAvailable wakes up goroutines that have been waiting for the
// non-nil network map that the control plane sends after reconnecting.
func (c *Client) NotifyNetMapAvailable() {
	if nm := c.nm.NetMapNoPeers(); nm == nil {
		return // client disconnected
	}
	var nextCh *chan struct{}
	for {
		ch := c.hasNetMap.Load()
		if ch == nil || *ch == nil {
			return // Client has been Closed
		}

		if nextCh == nil {
			nextCh = new(make(chan struct{})) // prepare for next non-nil netmap
		}
		if c.hasNetMap.CompareAndSwap(ch, nextCh) {
			close(*ch)
			return
		}
	}
}

func (c *Client) waitForNetMap(ctx context.Context) (*netmap.NetworkMap, error) {
	for {
		ch := c.hasNetMap.Load()
		if ch == nil || *ch == nil {
			return nil, errors.New("routecheck client closed")
		}

		if nm := c.nm.NetMapNoPeers(); nm != nil {
			return nm, nil
		}

		select {
		case <-c.ctx.Done(): // closed
			return nil, c.ctx.Err()
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-*ch: // woken up by NotifyNetMapAvailable
		}
	}
}

// Refresh generates and returns a new reachability report, after caching it in [Client.Report].
// A peer is considered unreachable if it doesn’t respond within the timeout.
// If the cached Client.Report is newer than the report that it just generated,
// Refresh will return the cached report instead of clobbering it report.
func (c *Client) Refresh(ctx context.Context, timeout time.Duration) (*Report, error) {
	metricRefresh.Add(1)
	c.vlogf("refreshing report")
	r, err := c.ProbeAllHARouters(ctx, 5, timeout)
	if err != nil {
		return nil, fmt.Errorf("error refreshing routers: %w", err)
	}
	for {
		saved := c.report.Load()
		if saved != nil && !saved.Done.Before(r.Done) {
			return saved, nil // don’t clobber newer reports
		}
		if c.report.CompareAndSwap(saved, r) { // retry if a concurrent Refresh stored first
			c.vlogf("saved new report at %v", r.Done)
			return r, nil
		}
	}
}

// NeedsRefresh signals the need for a [Client.Refresh] to probe for a new report,
// which will be done in the background by [Client.Start].
func (c *Client) NeedsRefresh() {
	if !IsEnabled(c.nb.NodeBackend().Self()) {
		return
	}

	select {
	case c.needsRefresh <- struct{}{}:
		metricNeedsRefresh.Add(1)
		c.vlogf("report needs refresh")
	default:
		// needsRefresh has already been raised, so debounce.
	}
}

// NeedsIncrRefresh signals the need for an incremental probe for a new report,
// because routers have been added, modified, or removed,
// which will be done in the background by [Client.Start].
func (c *Client) NeedsIncrRefresh(added, modified, removed []tailcfg.NodeID) {
	// TODO(sfllaw): Currently, this refreshes everything.
	c.NeedsRefresh()
}

// WatchForNetMonRebind watches the network monitor
// for a signal that the sockets need to be rebound,
// which implies that the cached report needs to be refreshed.
// See [netmon.ChangeDelta.RebindLikelyRequired].
func (c *Client) WatchForNetMonRebind(delta netmon.ChangeDelta) {
	if delta.RebindLikelyRequired {
		c.NeedsRefresh()
	}
}

// Start runs periodic probes that compile routecheck reports.
// Use [Client.Close] to stop probing.
// Returns an error if the client has already been closed.
func (c *Client) Start() error {
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}

	needsBootstrap := true
	for {
		select {
		case <-c.needsRefresh:
			nm := c.nm.NetMapWithPeers()
			if nm == nil {
				// There is no netmap: clear the cached report.
				c.report.Store(nil)
				needsBootstrap = true
				continue
			}

			if needsBootstrap {
				r := c.bootstrap(nm)
				c.report.Store(r)
				needsBootstrap = false
			}

			// TODO(sfllaw): Examine the shape of the overlapping
			// routers and only probe if the routing table has
			// changed sufficiently. For instance, a new router has
			// come online or a router has been removed or a set of
			// routers no longer overlap.
			if _, err := c.Refresh(c.ctx, DefaultTimeout); err != nil {
				c.logf("%v", err)
			}
		case <-c.ctx.Done(): // closed
			return nil
		}
	}
}

// bootstrap assumes that nodes that are connected to the control plane are reachable,
// while waiting for the first probe to finish.
//
// This function requires a netmap with peers.
func (c *Client) bootstrap(nm *netmap.NetworkMap) *Report {
	if nm == nil {
		return nil
	}

	can4, can6 := supportsIPVersions(c.nb.NodeBackend().Self())
	if !can4 && !can6 {
		return nil
	}
	addrFor := addrPicker(can4, can6)

	var r Report
	for _, nodes := range GroupRoutersByPrefix(nm.Peers) {
		if len(nodes) <= 1 {
			continue // Not an overlapping router
		}

		// TODO(sfllaw): Instead of trusting the Node.Online flag,
		// which actually represents whether the node is connected
		// to the control plane and not that it is reachable,
		// we should cache reachability alongside the cached netmap
		// long enough to survive a restart or a brief disconnection.
		for _, n := range nodes {
			if !n.Online().Get() {
				continue // Not connected to the control plane.
			}

			addr := addrFor(n)
			if !addr.IsValid() {
				continue // No valid addresses.
			}

			mak.Set(&r.Reachable, n.ID(), Node{
				ID:     n.ID(),
				Name:   n.Name(),
				Addr:   addr,
				Routes: routes(n),
			})
		}
	}
	r.Done = time.Now()
	c.vlogf("bootstrapped report from netmap at %v", r.Done)
	return &r
}

// Close immediately stops all active probes.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}

	if c.cancel != nil {
		c.cancel()
	}

	hasNetMap := c.hasNetMap.Swap(nil) // clear before waking anything up
	if hasNetMap != nil && *hasNetMap != nil {
		close(*hasNetMap) // wake waitForNetMap
	}

	return nil
}
