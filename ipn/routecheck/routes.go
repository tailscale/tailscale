// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck

import (
	"net/netip"

	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
)

// RoutersByPrefix represents a map of nodes grouped by the subnet that they route.
type RoutersByPrefix map[netip.Prefix][]tailcfg.NodeView

// RoutersByPrefix returns a map of nodes grouped by the subnet that they route.
// Nodes that route for /0 prefixes are exit nodes, their subnet is the Internet.
// The result omits any prefix that is one of a node’s local addresses.
func (c *Client) RoutersByPrefix() RoutersByPrefix {
	var routers RoutersByPrefix
	for _, n := range c.nb.NodeBackend().Peers() {
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
AllowedIPs:
	for _, pfx := range n.AllowedIPs().All() {
		// Routers never forward their own local addresses.
		for _, addr := range n.Addresses().All() {
			if pfx == addr {
				continue AllowedIPs
			}
		}
		routes = append(routes, pfx)
	}
	return routes
}
