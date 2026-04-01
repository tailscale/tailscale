// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package routecheck performs status checks for routes from the current host.
package routecheck

import (
	"context"
	"errors"
	"net/netip"

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
	nm     NetMapWaiter
	pinger Pinger
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
	}, nil
}
