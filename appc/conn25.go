// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"cmp"
	"slices"

	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/util/set"
)

const AppConnectorsExperimentalAttrName = "tailscale.com/app-connectors-experimental"

func isEligibleConnector(peer tailcfg.NodeView) bool {
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
		if !isEligibleConnector(n) {
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

func AppNameByDomain(hasCap func(c tailcfg.NodeCapability) bool, self tailcfg.NodeView) map[string]string {
	if !hasCap(AppConnectorsExperimentalAttrName) {
		return nil
	}
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](self.CapMap(), AppConnectorsExperimentalAttrName)
	if err != nil {
		return nil
	}
	appNamesByDomain := map[string]string{}
	for _, app := range apps {
		for _, domain := range app.Domains {
			// in the case of multiple apps specifying the same domain (which is misconfiguration
			// that should be validated at point of input) last write wins.
			appNamesByDomain[domain] = app.Name
		}
	}
	return appNamesByDomain
}
