// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package routesources contains the document with which the Tailscale
// Kubernetes operator tells a route acceptor device (containerboot in
// TS_EXPERIMENTAL_ROUTE_ACCEPTOR mode) which Pods on its node may be routed via
// the tailnet, and to which of the routes the device accepts. It is a separate
// package so that containerboot does not depend on the operator; be mindful of
// dependency size when adding to it.
package routesources

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"
)

const (
	// Version is the version of the document format.
	Version = 1

	// TableBase is the first routing table id a device uses for groups with
	// restricted routes and TableCount is how many tables follow it.
	// tailscaled itself uses table 52.
	TableBase  = 5300
	TableCount = 4096
)

// Document lists, for one node, which Pod addresses may be routed via the
// tailnet and to which routes. Everything else that the node forwards from the
// cluster's IP ranges follows the node's normal routes, as if there were no
// route acceptor.
type Document struct {
	Version int `json:"version"`
	// ClusterCIDRs are the IP ranges the cluster's Pods and Services use.
	// Traffic from them is only routed via the tailnet if its source is listed
	// in a group, and traffic to them never is.
	ClusterCIDRs []netip.Prefix `json:"clusterCIDRs"`
	// Groups are the Pod addresses that may be routed via the tailnet, grouped
	// by the routes they may reach.
	Groups []Group `json:"groups,omitempty"`
}

// Group is a set of Pod addresses that share a set of routes.
type Group struct {
	// Routes are the destinations the group's addresses may reach via the
	// tailnet; the device installs those of the routes it accepts that fall
	// within them. nil means every accepted route and every tailnet peer.
	Routes []netip.Prefix `json:"routes"`
	// Table is the routing table the device installs the group's routes in,
	// in [TableBase, TableBase+TableCount). It is 0 when Routes is nil, as the
	// device then uses tailscaled's own table. See TableFor.
	Table int `json:"table,omitempty"`
	// IPs are the addresses of the group's Pods.
	IPs []netip.Addr `json:"ips"`
}

// Parse decodes a document and checks its version and table ids.
func Parse(b []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("parsing route sources: %w", err)
	}
	if d.Version != Version {
		return nil, fmt.Errorf("unsupported route sources version %d, want %d", d.Version, Version)
	}
	for i, g := range d.Groups {
		if g.Routes == nil {
			continue
		}
		if g.Table < TableBase || g.Table >= TableBase+TableCount {
			return nil, fmt.Errorf("route sources group %d: routing table %d outside [%d, %d)", i, g.Table, TableBase, TableBase+TableCount)
		}
	}
	return &d, nil
}

// Normalize sorts the document's cluster CIDRs, groups and addresses and
// removes duplicates, so that two documents with the same content encode
// identically.
func (d *Document) Normalize() {
	d.ClusterCIDRs = sortedPrefixes(d.ClusterCIDRs)
	for i := range d.Groups {
		g := &d.Groups[i]
		if g.Routes != nil {
			g.Routes = sortedPrefixes(g.Routes)
		}
		slices.SortFunc(g.IPs, netip.Addr.Compare)
		g.IPs = slices.Compact(g.IPs)
	}
	slices.SortFunc(d.Groups, func(a, b Group) int {
		return cmp.Or(cmp.Compare(routesKey(a.Routes), routesKey(b.Routes)), cmp.Compare(a.Table, b.Table))
	})
}

// Marshal encodes the normalized document.
func (d *Document) Marshal() ([]byte, error) {
	d.Normalize()
	return json.Marshal(d)
}

// TableFor returns the routing table for a set of routes: a hash of the routes
// within [TableBase, TableBase+TableCount), probing past the tables in taken.
// Hashing keeps a group's table stable while other groups come and go, so that
// its Pods are never pointed at a table holding another group's routes. It
// returns an error if no table is free.
func TableFor(routes []netip.Prefix, taken map[int]bool) (int, error) {
	if len(taken) >= TableCount {
		return 0, errors.New("no free routing table")
	}
	h := fnv.New32a()
	h.Write([]byte(routesKey(routes)))
	start := int(h.Sum32() % TableCount)
	for i := range TableCount {
		t := TableBase + (start+i)%TableCount
		if !taken[t] {
			return t, nil
		}
	}
	return 0, errors.New("no free routing table")
}

// routesKey is a canonical string for a set of routes.
func routesKey(routes []netip.Prefix) string {
	if routes == nil {
		return ""
	}
	pfxs := sortedPrefixes(routes)
	strs := make([]string, len(pfxs))
	for i, p := range pfxs {
		strs[i] = p.String()
	}
	return strings.Join(strs, ",")
}

func sortedPrefixes(pfxs []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(pfxs))
	for _, p := range pfxs {
		if p.IsValid() {
			out = append(out, p.Masked())
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	return slices.Compact(out)
}
