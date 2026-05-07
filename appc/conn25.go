// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"cmp"
	"slices"
	"strings"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

const AppConnectorsExperimentalAttrName = "tailscale.com/app-connectors-experimental"

func isPeerEligibleConnector(peer tailcfg.NodeView) bool {
	if !peer.Valid() || !peer.Hostinfo().Valid() {
		return false
	}
	isConn, _ := peer.Hostinfo().AppConnector().Get()
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

// PickConnector returns peers the backend knows about that match the app, in order of preference to use as
// a connector.
func PickConnector(nb ipnext.NodeBackend, app appctype.Conn25Attr) []tailcfg.NodeView {
	appTagsSet := set.SetOf(app.Connectors)
	matches := nb.AppendMatchingPeers(nil, func(n tailcfg.NodeView) bool {
		if !isPeerEligibleConnector(n) {
			return false
		}
		for _, t := range n.Tags().All() {
			if appTagsSet.Contains(t) {
				return true
			}
		}
		return false
	})
	sortByPreference(matches)
	return matches
}

// PickSplitDNSPeers looks at the netmap peers capabilities and finds which peers
// want to be connectors for which domains.
func PickSplitDNSPeers(hasCap func(c tailcfg.NodeCapability) bool, self tailcfg.NodeView, peers map[tailcfg.NodeID]tailcfg.NodeView, isSelfEligibleConnector bool) map[string][]tailcfg.NodeView {
	var m map[string][]tailcfg.NodeView
	if !hasCap(AppConnectorsExperimentalAttrName) {
		return m
	}
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](self.CapMap(), AppConnectorsExperimentalAttrName)
	if err != nil {
		return m
	}

	// We strip the leading *. from any domains because the OS treats all domains
	// that we pass to it as wildcard domains, and the OS would treat the * character
	// as a literal domain component instead of treating it as a wildcard.
	// We also use a Set to deduplicate the domains we pass to the OS in case removing
	// the *. prefix resulted in duplicate entries.
	tagToDomain := make(map[string]set.Set[string])
	selfTags := set.SetOf(self.Tags().AsSlice())
	selfRoutedDomains := set.Set[string]{}
	for _, app := range apps {
		domains := make(set.Set[string])
		for _, domain := range app.Domains {
			domains.Add(strings.ToLower(strings.TrimPrefix(domain, "*.")))
		}
		for _, tag := range app.Connectors {
			if tagToDomain[tag] == nil {
				tagToDomain[tag] = set.Set[string]{}
			}
			tagToDomain[tag].AddSet(domains)
			if isSelfEligibleConnector && selfTags.Contains(tag) {
				selfRoutedDomains.AddSet(domains)
			}
		}
	}
	// NodeIDs are Comparable, and we have a map of NodeID to NodeView anyway, so
	// use a Set of NodeIDs to deduplicate, and populate into a []NodeView later.
	var work map[string]set.Set[tailcfg.NodeID]
	for _, peer := range peers {
		if !isPeerEligibleConnector(peer) {
			continue
		}
		for _, t := range peer.Tags().All() {
			domains := tagToDomain[t]
			for domain := range domains {
				if selfRoutedDomains.Contains(domain) {
					continue
				}
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
