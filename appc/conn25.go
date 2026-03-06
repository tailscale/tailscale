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

func isEligibleConnector(n tailcfg.NodeView) bool {
	if !n.Valid() || !n.Hostinfo().Valid() {
		return false
	}
	isConn, _ := n.Hostinfo().AppConnector().Get()
	return isConn
}

func sortByPreference(ns []tailcfg.NodeView) {
	// The ordering of the nodes is semantic (callers use the first node they can
	// get a peer api url for). We don't (currently 2026-02-27) have any
	// preference over which node is chosen as long as it's consistent.  In the
	// future we anticipate integrating with traffic steering.
	slices.SortFunc(ns, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
}

// PickConnector returns nodes from candidates that match the app, in order of preference to use as
// a connector.
func PickConnector(candidates []tailcfg.NodeView, app appctype.Conn25Attr) []tailcfg.NodeView {
	appTagsSet := set.SetOf(app.Connectors)
	matches := []tailcfg.NodeView{}
	for _, n := range candidates {
		if !isEligibleConnector(n) {
			continue
		}
		for _, t := range n.Tags().All() {
			if appTagsSet.Contains(t) {
				matches = append(matches, n)
				break
			}
		}
	}
	sortByPreference(matches)
	return matches
}

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
		if !isEligibleConnector(peer) {
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
		sortByPreference(nodes)
		mak.Set(&m, domain, nodes)
	}
	return m
}
