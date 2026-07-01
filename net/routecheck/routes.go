// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"net/netip"

	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
)

// RoutersByPrefix represents a map of nodes grouped by the subnet that they route.
// Nodes that route for /0 prefixes are exit nodes, their subnet is the Internet.
// The result omits any prefix that is one of a node’s local addresses.
//
// Note: Fallback routes are not supported by design. If a subnet prefix
// contained within another more general prefix has no reachable routers,
// traffic is still sent to one of those unreachable routers.
// Routers for the general prefix aren’t candidates. See tailscale/tailscale#18550.
type RoutersByPrefix map[netip.Prefix][]tailcfg.NodeView

// RoutersByPrefix returns a map of nodes grouped by the subnet that they route.
// See [RoutersByPrefix] for more detail.
func (c *Client) RoutersByPrefix() RoutersByPrefix {
	return GroupRoutersByPrefix(c.nb.NodeBackend().Peers())
}

// GroupRoutersByPrefix returns a map of nodes grouped by the subnet that they route.
// See [RoutersByPrefix] for more detail.
func GroupRoutersByPrefix(nodes []tailcfg.NodeView) RoutersByPrefix {
	var routers RoutersByPrefix
	for _, n := range nodes {
		for _, pfx := range routes(n) {
			mak.Set(&routers, pfx, append(routers[pfx], n))
		}
	}
	return routers
}

// Routes returns a slice of subnets that the given node will route.
// If the node is an exit node, the result will contain at least one /0 prefix.
// If the node is a subnet router, the result will contain a smaller prefix.
// The result omits any prefix that is one of the node’s local addresses.
func routes(n tailcfg.NodeView) []netip.Prefix {
	var routes []netip.Prefix
	for _, pfx := range n.AllowedIPs().All() {
		// Routers never forward their own local addresses.
		if views.SliceContains(n.Addresses(), pfx) {
			continue
		}
		routes = append(routes, pfx)
	}
	return routes
}
