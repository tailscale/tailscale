// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"cmp"
	"slices"

	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const AppConnectorsExperimentalAttrName = "tailscale.com/app-connectors-experimental"

// PickSplitDNSPeers looks at the netmap peers capabilities and finds which peers
// want to be connectors for which domains.
func PickSplitDNSPeers(hasCap func(c tailcfg.NodeCapability) bool, self tailcfg.NodeView, peers map[tailcfg.NodeID]tailcfg.NodeView) map[string][]tailcfg.NodeView {
	var m map[string][]tailcfg.NodeView
	if !hasCap(AppConnectorsExperimentalAttrName) {
		return m
	}
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](self.CapMap(), AppConnectorsExperimentalAttrName)
	if err != nil {
		return m
	}
	tagToDomain := make(map[string][]string)
	for _, app := range apps {
		for _, tag := range app.Connectors {
			tagToDomain[tag] = append(tagToDomain[tag], app.Domains...)
		}
	}
	// NodeIDs are Comparable, and we have a map of NodeID to NodeView anyway, so
	// use a Set of NodeIDs to deduplicate, and populate into a []NodeView later.
	var work map[string]set.Set[tailcfg.NodeID]
	for _, peer := range peers {
		if !peer.Valid() || !peer.Hostinfo().Valid() {
			continue
		}
		if isConn, _ := peer.Hostinfo().AppConnector().Get(); !isConn {
			continue
		}
		for _, t := range peer.Tags().All() {
			domains := tagToDomain[t]
			for _, domain := range domains {
				if work[domain] == nil {
					mak.Set(&work, domain, set.Set[tailcfg.NodeID]{})
				}
				work[domain].Add(peer.ID())
			}
		}
	}

	// Populate m. Make a []tailcfg.NodeView from []tailcfg.NodeID using the peers map.
	// And sort it to our preference.
	for domain, ids := range work {
		nodes := make([]tailcfg.NodeView, 0, ids.Len())
		for id := range ids {
			nodes = append(nodes, peers[id])
		}
		// The ordering of the nodes in the map vals is semantic (dnsConfigForNetmap uses the first node it can
		// get a peer api url for as its split dns target). We can think of it as a preference order, except that
		// we don't (currently 2026-01-14) have any preference over which node is chosen.
		slices.SortFunc(nodes, func(a, b tailcfg.NodeView) int {
			return cmp.Compare(a.ID(), b.ID())
		})
		mak.Set(&m, domain, nodes)
	}
	return m
}
