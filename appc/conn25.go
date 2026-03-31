// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

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

// NormalizeDNSName normalizes the DNS name to a lower-case [dnsname.FQDN].
func NormalizeDNSName(name string) (dnsname.FQDN, error) {
	// note that appconnector does this same thing, tsdns has its own custom lower casing
	// it might be good to unify in a function in dnsname package.
	return dnsname.ToFQDN(strings.ToLower(name))
}

// ConnectorSelfRoutedDomains returns the set of domains from all apps that could potentially
// apply to self, if self is an eligible connector. self does not have reliable information to
// determine if it is an eligible connector. So callers of this method are expected to make
// that determination separately.
func ConnectorSelfRoutedDomains(self tailcfg.NodeView, apps []appctype.Conn25Attr) (set.Set[dnsname.FQDN], error) {
	selfTags := set.SetOf(self.Tags().AsSlice())

	selfRoutedDomains := set.Set[dnsname.FQDN]{}
	for _, app := range apps {
		if !slices.ContainsFunc(app.Connectors, selfTags.Contains) {
			continue
		}
		for _, d := range app.Domains {
			fqdn, err := NormalizeDNSName(d)
			if err != nil {
				return nil, fmt.Errorf("could not normalize domain %q: %w", d, err)
			}
			selfRoutedDomains.Add(fqdn)
		}
	}
	return selfRoutedDomains, nil
}

// PickSplitDNSPeers looks at the netmap peers capabilities and finds which peers
// want to be connectors for which domains.
func PickSplitDNSPeers(hasCap func(c tailcfg.NodeCapability) bool, self tailcfg.NodeView, peers map[tailcfg.NodeID]tailcfg.NodeView, isSelfEligibleConnector bool) (map[dnsname.FQDN][]tailcfg.NodeView, error) {
	if !hasCap(appctype.AppConnectorsExperimentalAttrName) {
		return nil, nil
	}
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.Conn25Attr](self.CapMap(), appctype.AppConnectorsExperimentalAttrName)
	if err != nil {
		return nil, err
	}

	if len(apps) == 0 {
		return nil, nil
	}

	var selfRoutedDomains set.Set[dnsname.FQDN]
	if isSelfEligibleConnector {
		selfRoutedDomains, err = ConnectorSelfRoutedDomains(self, apps)
		if err != nil {
			return nil, err
		}
	}
	tagToDomain := make(map[string][]dnsname.FQDN)
	for _, app := range apps {
		for _, tag := range app.Connectors {
			for _, d := range app.Domains {
				fqdn, err := NormalizeDNSName(d)
				if err != nil {
					return nil, err
				}
				if selfRoutedDomains != nil && selfRoutedDomains.Contains(fqdn) {
					continue
				}
				tagToDomain[tag] = append(tagToDomain[tag], fqdn)
			}
		}
	}

	// NodeIDs are Comparable, and we have a map of NodeID to NodeView anyway, so
	// use a Set of NodeIDs to deduplicate, and populate into a []NodeView later.
	var work map[dnsname.FQDN]set.Set[tailcfg.NodeID]
	for _, peer := range peers {
		if !isPeerEligibleConnector(peer) {
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
	var m map[dnsname.FQDN][]tailcfg.NodeView
	for domain, ids := range work {
		nodes := make([]tailcfg.NodeView, 0, ids.Len())
		for id := range ids {
			nodes = append(nodes, peers[id])
		}
		sortByPreference(nodes)
		mak.Set(&m, domain, nodes)
	}
	return m, nil
}
