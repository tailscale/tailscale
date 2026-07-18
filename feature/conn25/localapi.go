// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"cmp"
	"encoding/json"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"tailscale.com/envknob"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/types/appctype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/httpm"
	"tailscale.com/util/mak"
	"tailscale.com/util/testenv"
)

// serveStateGet serves the localapi endpoint /conn25-state.
// See also [*Conn25.GetActiveState].
func serveStateGet(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	// TODO(tailscale/corp#39033): Remove for alpha release.
	if !envknob.UseWIPCode() && !testenv.InTest() {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	if !h.PermitRead {
		http.Error(w, "conn25-state access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	ext, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		http.Error(w, "miswired", http.StatusInternalServerError)
		return
	}
	state := ext.conn25.GetActiveState()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(state); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// GetActiveState returns active state for the client and the connector,
// including IP pool usage, address mappings, domains, and active flow counts.
func (c *Conn25) GetActiveState() appctype.Conn25ActiveState {
	if !c.isConfigured() {
		return appctype.Conn25ActiveState{}
	}

	return appctype.Conn25ActiveState{
		Configured: true,
		Client:     c.client.getActiveState(),
		Connector:  c.connector.getActiveState(),
	}
}

// getActiveState gets active state from the client.
// See [appctype.Conn25ClientState] for structure.
func (c *client) getActiveState() appctype.Conn25ClientState {
	c.mu.Lock()
	defer c.mu.Unlock()

	var appToDomains map[string]map[dnsname.FQDN][]appctype.Conn25ClientAddressState

	// Pre-sort addresses by destination IP. They'll later be primary sorted
	// by active flow count.
	domainDstKeys := slices.Collect(maps.Keys(c.assignments.byDomainDst))
	slices.SortFunc(domainDstKeys, func(a, b domainDst) int {
		return a.dst.Compare(b.dst)
	})

	for _, domainDstKey := range domainDstKeys {
		assignment := c.assignments.byDomainDst[domainDstKey]
		domainMap := appToDomains[assignment.app]
		addresses := domainMap[assignment.domain]
		addresses = append(addresses, appctype.Conn25ClientAddressState{
			ActiveFlowCount: assignment.activeFlowCount,
			DestinationIP:   assignment.dst.String(),
			MagicIP:         assignment.magic.String(),
			TransitIP:       assignment.transit.String(),
			ExpiresAt:       assignment.expiresAt,
		})

		mak.Set(&domainMap, assignment.domain, addresses)
		mak.Set(&appToDomains, assignment.app, domainMap)
	}

	var apps []appctype.Conn25ClientAppState
	for appName, domainMap := range appToDomains {
		var app appctype.Conn25ClientAppState
		app.App = appName
		for domain, addresses := range domainMap {
			var domainState appctype.Conn25ClientDomainState
			domainState.Domain = domain

			// Sort address mappings by descending active flow count.
			slices.SortStableFunc(addresses, func(a, b appctype.Conn25ClientAddressState) int {
				if a.ActiveFlowCount > b.ActiveFlowCount {
					return -1
				}
				if a.ActiveFlowCount < b.ActiveFlowCount {
					return 1
				}
				return 0
			})
			domainState.Addresses = addresses
			app.Domains = append(app.Domains, domainState)
		}

		// Sort domains by hierarchy, e.g. "example.com", "sub.example.com".
		slices.SortFunc(app.Domains, compareFQDNHierarchical)
		apps = append(apps, app)
	}

	// Sort apps lexicographically.
	slices.SortFunc(apps, func(a, b appctype.Conn25ClientAppState) int {
		return strings.Compare(a.App, b.App)
	})

	return appctype.Conn25ClientState{
		Apps: apps,
		IPPoolStats: appctype.Conn25ClientIPPoolStats{
			IPv4MagicIPsInUse:      c.v4MagicIPPool.inUseCount(),
			IPv4MagicIPsCapacity:   c.v4MagicIPPool.capacity(),
			IPv6MagicIPsInUse:      c.v6MagicIPPool.inUseCount(),
			IPv6MagicIPsCapacity:   c.v6MagicIPPool.capacity(),
			IPv4TransitIPsInUse:    c.v4TransitIPPool.inUseCount(),
			IPv4TransitIPsCapacity: c.v4TransitIPPool.capacity(),
			IPv6TransitIPsInUse:    c.v6TransitIPPool.inUseCount(),
			IPv6TransitIPsCapacity: c.v6TransitIPPool.capacity(),
		},
	}
}

// getActiveState gets active state from the connector.
// See [appctype.Conn25ConnectorState] for structure.
func (c *connector) getActiveState() appctype.Conn25ConnectorState {
	c.mu.Lock()
	defer c.mu.Unlock()

	var peers []appctype.Conn25ConnectorPeerState
	// Sort peers by client IP.
	for _, clientIP := range slices.SortedFunc(maps.Keys(c.transitIPs), netip.Addr.Compare) {
		transitToAddr := c.transitIPs[clientIP]
		var appToAddrs map[string][]appctype.Conn25ConnectorAddressState

		// Sort address mappings by transit IP.
		for _, transitIP := range slices.SortedFunc(maps.Keys(transitToAddr), netip.Addr.Compare) {
			addr := transitToAddr[transitIP]
			apiAddr := appctype.Conn25ConnectorAddressState{
				DestinationIP: addr.addr.String(),
				TransitIP:     transitIP.String(),
			}
			mak.Set(&appToAddrs, addr.app, append(appToAddrs[addr.app], apiAddr))
		}

		var apps []appctype.Conn25ConnectorAppState
		for appName, addrs := range appToAddrs {
			apps = append(apps, appctype.Conn25ConnectorAppState{
				App:       appName,
				Addresses: addrs,
			})
		}

		// Sort apps lexicographically.
		slices.SortFunc(apps, func(a, b appctype.Conn25ConnectorAppState) int {
			return strings.Compare(a.App, b.App)
		})

		peers = append(peers, appctype.Conn25ConnectorPeerState{
			ClientIP: clientIP.String(),
			Apps:     apps,
		})
	}

	return appctype.Conn25ConnectorState{Peers: peers}
}

// compareFQDNHierarchical sorts [appctype.Conn25ClientDomainState] hierarchically
// such that parents precede their children, e.g. "example.com" precedes
// "sub.example.com". If two domains aren't related, they are sorted lexicographically
// from the root and moving forward, e.g. "example.com" precedes "abc.org".
func compareFQDNHierarchical(ad, bd appctype.Conn25ClientDomainState) int {
	a, b := ad.Domain, bd.Domain
	al := strings.Split(a.WithoutTrailingDot(), ".")
	bl := strings.Split(b.WithoutTrailingDot(), ".")
	for i := 1; i <= len(al) && i <= len(bl); i++ {
		if c := strings.Compare(al[len(al)-i], bl[len(bl)-i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(al), len(bl))
}
