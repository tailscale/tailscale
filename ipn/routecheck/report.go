// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"context"
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
)

// Report returns the latest reachability report.
// Returns nil if a report isn’t available, which happens during initialization.
func (c *Client) Report() *Report {
	nm := c.nm.NetMap()
	if nm == nil {
		return nil // The report wasn’t available.
	}

	// TODO(sfllaw): Return the latest snapshot produced by background probing.
	r, err := c.ProbeAllHARouters(context.TODO(), 5, DefaultTimeout)
	if err != nil {
		c.logf("reachability report error: %v", err)
	}
	return r
}

// Report contains the result of a single routecheck.
type Report struct {
	// Done is the time when the report was finished.
	Done time.Time

	// Reachable is the set of nodes that were reachable from the current host
	// when this report was compiled. Missing nodes may or may not be reachable.
	Reachable map[tailcfg.NodeID]Node
}

// Node represents a node in the reachability report.
type Node struct {
	ID tailcfg.NodeID

	// Name is the FQDN of the node.
	// It is also the MagicDNS name for the node.
	// It has a trailing dot.
	// e.g. "host.tail-scale.ts.net."
	Name string

	// Addr is the IP address that was probed.
	Addr netip.Addr

	// Routes are the subnets that the node will route.
	Routes []netip.Prefix
}
