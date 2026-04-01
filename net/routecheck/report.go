// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"

	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
)

var (
	metricReport = clientmetric.NewCounter("routecheck_report")
)

// Report returns the latest reachability report.
// Returns nil if a report isn’t available, which happens during initialization.
func (c *Client) Report() *Report {
	metricReport.Add(1)
	nm := c.nm.NetMapNoPeers()
	if nm == nil {
		return nil // The report wasn’t available.
	}

	// TODO(sfllaw): Return the latest snapshot produced by background probing.
	r, err := c.Refresh(context.TODO(), DefaultTimeout)
	if err != nil {
		c.logf("%v", err)
	}
	return r
}

// Report contains the result of a single routecheck.
type Report struct {
	// Done is the time when the report was finished.
	Done time.Time `json:"done"`

	// Reachable is the set of nodes that were reachable from the current host
	// when this report was compiled. Missing nodes may or may not be reachable.
	Reachable nodeset `json:"reachable"`

	// LastProbed tracks the last time a given node was probed.
	// This is used to rate-limit reachability probing, so an entry’s
	// presence doesn’t imply that it is reachable.
	LastProbed map[tailcfg.NodeID]time.Time
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

var _ jsonv2.MarshalerTo = nodeset{}
var _ jsonv2.UnmarshalerFrom = nodeset{}

// MarshalJSONTo implements [jsonv2.MarshalerTo].
func (ns nodeset) MarshalJSONTo(enc *jsontext.Encoder) error {
	nodes := maps.Values(ns)
	return jsonv2.MarshalEncode(enc, slices.Collect(nodes))
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom].
func (ns nodeset) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var nodes []Node
	if err := jsonv2.UnmarshalDecode(dec, &nodes); err != nil {
		return err
	}
	for _, n := range nodes {
		ns[n.ID] = n
	}
	return nil
}
