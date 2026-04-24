// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"encoding/json"
	"maps"
	"net/netip"
	"slices"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
)

// Report returns the latest reachability report.
// Returns nil if a report isn’t available, which happens during initialization.
func (c *Client) Report() *Report {
	return c.report.Load()
}

// Report contains the result of a single routecheck.
type Report struct {
	// Done is the time when the report was finished.
	Done time.Time `json:"done"`

	// Reachable is the set of nodes that were reachable from the current host
	// when this report was compiled. Missing nodes may or may not be reachable.
	Reachable nodeset `json:"reachable"`
}

// IsReachable reports whether a peer is reachable by the current node
// or if it is unknown because it has yet to be probed.
func (rp Report) IsReachable(id tailcfg.NodeID) (ok, known bool) {
	// TODO(sfllaw): We should actually track all routers and consider the
	// absence of a router in the report as it being recently added for
	// consideration, so it is unknown. Then we should positively track
	// whether a node was reachable or not.
	_, k := rp.Reachable[id]
	return k, k
}

// RoutablePrefixes returns a [RoutingTable] mapping routable network prefixes
// with the associated routers that were reachable by the current host,
// at the time the report was finished.
func (rp Report) RoutablePrefixes() RoutingTable {
	var out map[netip.Prefix][]Node
	for _, n := range rp.Reachable {
		for _, p := range n.Routes {
			mak.Set(&out, p, append(out[p], n))
		}
	}
	return out
}

// Node represents a node in the reachability report.
type Node struct {
	ID tailcfg.NodeID `json:"id"`

	// Name is the FQDN of the node.
	// It is also the MagicDNS name for the node.
	// It has a trailing dot.
	// e.g. "host.tail-scale.ts.net."
	Name string `json:"name"`

	// Addr is the IP address that was probed.
	Addr netip.Addr `json:"addr"`

	// Routes are the subnets that the node will route.
	Routes []netip.Prefix `json:"routes"`
}

// Nodeset is a set of nodes keyed by node ID, so duplicates are easily detected.
// To prevent stuttering, it encodes itself as an array.
type nodeset map[tailcfg.NodeID]Node

var _ json.Marshaler = nodeset{}
var _ json.Unmarshaler = nodeset{}

// MarshalJSON implements the [json.Marshaler] interface.
func (ns nodeset) MarshalJSON() ([]byte, error) {
	nodes := maps.Values(ns)
	return json.Marshal(slices.Collect(nodes))
}

// MarshalJSON implements the [json.Unmarshaler] interface.
func (ns nodeset) UnmarshalJSON(b []byte) error {
	var nodes []Node
	if err := json.Unmarshal(b, &nodes); err != nil {
		return err
	}
	for _, n := range nodes {
		ns[n.ID] = n
	}
	return nil
}

// RoutingTable is a map of routers, keyed by the network prefix for which they route.
type RoutingTable map[netip.Prefix][]Node
