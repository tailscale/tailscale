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

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
)

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
	nm     NetMapWaiter
	pinger Pinger

	needsRefresh chan struct{} // used to signal the need for refresh
	stop         context.CancelFunc
	report       atomic.Pointer[Report]
}

// NetMapWaiter is the interface that returns the current [netmap.NetworkMap].
type NetMapWaiter interface {
	// NetMap returns the latest cached network map received from controlclient,
	// or nil if no network map was received yet.
	NetMap() *netmap.NetworkMap

	// WaitForNetMap returns the latest cached network map received from controlclient,
	// or waits for until the initial network map has been received.
	WaitForNetMap(context.Context) (*netmap.NetworkMap, error)
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

// Pinger is the interface that wraps the [ipnlocal.LocalBackend.Ping] method.
type Pinger interface {
	Ping(ip netip.Addr, pingType tailcfg.PingType, size int, cb func(*ipnstate.PingResult))
}

// NewClient returns a client that probes its peers using this LocalBackend.
func NewClient(logf logger.Logf, nb NodeBackender, nm NetMapWaiter, pinger Pinger) (*Client, error) {
	if nb == nil {
		return nil, errors.New("NodeBackender must be set")
	}
	if nm == nil {
		return nil, errors.New("NetMapWaiter must be set")
	}
	if pinger == nil {
		return nil, errors.New("Pinger must be set")
	}

	return &Client{
		Logf:   logf,
		nb:     nb,
		nm:     nm,
		pinger: pinger,

		needsRefresh: make(chan struct{}, 1),
	}, nil
}

// Refresh generates a new reachability report and returns it.
// A peer is considered unreachable if it doesn’t respond within the timeout.
func (c *Client) Refresh(ctx context.Context, timeout time.Duration) (*Report, error) {
	r, err := c.ProbeAllHARouters(ctx, 5, timeout)
	if err != nil {
		return nil, fmt.Errorf("error probing routers: %w", err)
	}
	return r, nil
}

// NeedsRefresh signals the need for a [Client.Refresh], which will be done in the background.
func (c *Client) NeedsRefresh() {
	select {
	case c.needsRefresh <- struct{}{}:
	default:
	}
}

// Start
func (c *Client) Start(ctx context.Context) {
	first := true
	ctx, cancel := context.WithCancel(ctx)
	c.stop = cancel
	for {
		select {
		case <-c.needsRefresh:
			nm := c.nm.NetMap()
			if nm == nil {
				continue // The report wasn’t available.
			}

			if first {
				r := c.bootstrap(nm)
				c.report.Store(r)
				first = false
			}

			// TODO(sfllaw): Examine the shape of the overlapping
			// routers and only probe if the routing table has
			// changed sufficiently. For instance, a new router has
			// come online or a router has been removed or a set of
			// routers no longer overlap.

			r, err := c.Refresh(ctx, DefaultTimeout)
			if err != nil {
				c.logf("%v", err)
				continue
			}
			c.report.Store(r)
		case <-ctx.Done():
			return
		}
	}
}

// Bootstrap assumes that nodes that are connected to the control plane are reachable,
// while waiting for the first probe to finish.
func (c *Client) bootstrap(nm *netmap.NetworkMap) *Report {
	if nm == nil {
		return nil
	}

	canIPv4, canIPv6 := supportsIPVersions(c.nb.NodeBackend().Self())
	if !(canIPv4 || canIPv6) {
		return nil
	}

	var r Report
	for _, n := range nm.Peers {
		for _, ip := range n.Addresses().All() {
			// Match the IP versions
			addr := ip.Addr()
			if addr.Is4() && !canIPv4 {
				continue
			}
			if addr.Is6() && !canIPv6 {
				continue
			}

			mak.Set(&r.Reachable, n.ID(), Node{
				ID:     n.ID(),
				Name:   n.Name(),
				Addr:   addr,
				Routes: routes(n),
			})
			break
		}
	}
	r.Done = time.Now()
	return &r
}

// Close
func (c *Client) Close() error {
	if c == nil {
		return nil
	}

	close(c.needsRefresh)
	if c.stop != nil {
		c.stop()
	}
	return nil
}
