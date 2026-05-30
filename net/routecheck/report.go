// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"cmp"
	"context"
	"iter"
	"maps"
	"net/netip"
	"slices"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	jsonv1 "github.com/go-json-experiment/json/v1"

	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/mak"
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
	Reachable NodeSet `json:"reachable"`

	// LastProbed tracks the last time a given node was probed.
	// This is used to rate-limit reachability probing, so an entry’s
	// presence doesn’t imply that it is reachable.
	LastProbed map[tailcfg.NodeID]time.Time `json:"-"` // not marshaled
}

// RoutablePrefixes returns a map of routable network prefixes associated with
// each prefix’s routers that were reachable by the current host,
// at the time the report was finished.
// Each slice of routers are ordered by their node ID.
//
// Note: Fallback routes are not supported by design. If a subnet prefix
// contained within another more general prefix has no reachable routers,
// traffic is still sent to one of those unreachable routers.
// Routers for the general prefix aren’t candidates. See tailscale/tailscale#18550.
func (rp Report) RoutablePrefixes() RoutablePrefixes {
	var out map[netip.Prefix][]Node
	for _, n := range rp.Reachable {
		for _, p := range n.Routes {
			mak.Set(&out, p, append(out[p], n))
		}
	}
	for p := range out {
		slices.SortFunc(out[p], Node.Compare)
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

// Compare returns an integer comparing two nodes, ordered by their node ID.
// The result will be 0 if n.ID == n2.ID, -1 if n.ID < n2.ID, and +1 if n.ID > n2.ID.
func (n Node) Compare(n2 Node) int {
	return cmp.Compare(n.ID, n2.ID)
}

// NodeSet is a set of nodes keyed by node ID, so duplicates are easily detected.
// To prevent stuttering, it marshals itself as a JSON array, sorted by node ID.
type NodeSet map[tailcfg.NodeID]Node

var (
	_ jsonv1.Marshaler       = &NodeSet{}
	_ jsonv1.Unmarshaler     = &NodeSet{}
	_ jsonv2.MarshalerTo     = &NodeSet{}
	_ jsonv2.UnmarshalerFrom = &NodeSet{}
)

// MarshalJSONTo implements [jsonv2.MarshalerTo].
func (ns NodeSet) MarshalJSONTo(enc *jsontext.Encoder) error {
	nodes := slices.SortedFunc(maps.Values(ns), Node.Compare)
	return jsonv2.MarshalEncode(enc, nodes)
}

// UnmarshalJSONFrom implements [jsonv2.UnmarshalerFrom].
func (ns *NodeSet) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var nodes []Node
	if err := jsonv2.UnmarshalDecode(dec, &nodes); err != nil {
		return err
	}
	if *ns == nil {
		*ns = make(NodeSet, len(nodes))
	}
	for _, n := range nodes {
		(*ns)[n.ID] = n
	}
	return nil
}

// MarshalJSON implements [jsonv1.Marshaler].
func (ns *NodeSet) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(ns, jsonv1.DefaultOptionsV1())
}

// UnmarshalJSON implements [jsonv1.Unmarshaler].
func (ns *NodeSet) UnmarshalJSON(b []byte) error {
	return jsonv2.Unmarshal(b, ns, jsonv1.DefaultOptionsV1())

}

// RoutablePrefixes is a map of routers,
// keyed by the network prefix for which they route.
type RoutablePrefixes map[netip.Prefix][]Node

// Sorted returns an iterator over the map of routers,
// ordered by the network prefix as described in [netip.Prefix.Compare].
func (rt RoutablePrefixes) Sorted() iter.Seq2[netip.Prefix, []Node] {
	return func(yield func(netip.Prefix, []Node) bool) {
		prefixes := slices.SortedFunc(maps.Keys(rt), netip.Prefix.Compare)
		for _, p := range prefixes {
			if !yield(p, rt[p]) {
				return
			}
		}
	}
}
