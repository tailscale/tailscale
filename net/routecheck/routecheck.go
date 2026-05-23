// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package routecheck performs status checks for routes from the current host.
package routecheck

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
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
	nm     NetMapper
	pinger Pinger

	// NetMapAvailable is raised when the first network map is received
	// after connecting to the control plane.
	netMapAvailable sync.Cond
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
func NewClient(logf logger.Logf, nb NodeBackender, nm NetMapper, pinger Pinger) (*Client, error) {
	if nb == nil {
		return nil, errors.New("NodeBackender must be set")
	}
	if nm == nil {
		return nil, errors.New("NetMapper must be set")
	}
	if pinger == nil {
		return nil, errors.New("Pinger must be set")
	}
	c := &Client{
		Logf:   logf,
		nb:     nb,
		nm:     nm,
		pinger: pinger,
	}
	c.netMapAvailable.L = new(sync.Mutex)
	return c, nil
}

func (c *Client) NetMapAvailable(nm *netmap.NetworkMap) {
	if nm == nil {
		return // client disconnected
	}
	c.netMapAvailable.Broadcast()
}

func (c *Client) waitForNetMap(ctx context.Context) (*netmap.NetworkMap, error) {
	cond := &c.netMapAvailable
	cond.L.Lock()
	defer cond.L.Unlock()

	stopf := context.AfterFunc(ctx, func() {
		// Lock cond to ensure that Broadcast is called after the Wait below.
		cond.L.Lock()
		defer cond.L.Unlock()
		cond.Broadcast()
	})
	defer stopf()

	for {
		nm := c.nm.NetMapNoPeers()
		if nm != nil {
			return nm, nil
		}
		cond.Wait()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

// Close immediately stops all active probes.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}

	c.netMapAvailable.Broadcast() // Wake goroutines in waitForNetMap.

	return nil
}
