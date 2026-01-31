// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"

	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

type appAddr struct {
	app  string
	addr netip.Addr
}

// Conn25 holds state for routing traffic for a domain via a connector.
type Conn25 struct {
	client client
	server server
}

func NewConn25() *Conn25 {
	return &Conn25{
		client: client{},
		server: server{},
	}
}

func (c *Conn25) Reconfig(nm *netmap.NetworkMap) error {
	return nil
}

func (c *Conn25) MapDNSResponse(buf []byte) []byte {
	return buf
}

const dupeTransitIPMessage = "Duplicate transit address in ConnectorTransitIPRequest"

// HandleConnectorTransitIPRequest creates a ConnectorTransitIPResponse in response to a ConnectorTransitIPRequest.
// It updates the connectors mapping of TransitIP->DestinationIP per peer (tailcfg.NodeID).
// If a peer has stored this mapping in the connector Conn25 will route traffic to TransitIPs to DestinationIPs for that peer.
func (c *Conn25) HandleConnectorTransitIPRequest(nid tailcfg.NodeID, ctipr ConnectorTransitIPRequest) ConnectorTransitIPResponse {
	resp := ConnectorTransitIPResponse{}
	seen := map[netip.Addr]bool{}
	for _, each := range ctipr.TransitIPs {
		if seen[each.TransitIP] {
			resp.TransitIPs = append(resp.TransitIPs, TransitIPResponse{
				Code:    OtherFailure,
				Message: dupeTransitIPMessage,
			})
			continue
		}
		tipresp := c.server.handleTransitIPRequest(nid, each)
		seen[each.TransitIP] = true
		resp.TransitIPs = append(resp.TransitIPs, tipresp)
	}
	return resp
}

func (s *server) handleTransitIPRequest(nid tailcfg.NodeID, tipr TransitIPRequest) TransitIPResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.transitIPs == nil {
		s.transitIPs = make(map[tailcfg.NodeID]map[netip.Addr]appAddr)
	}
	peerMap, ok := s.transitIPs[nid]
	if !ok {
		peerMap = make(map[netip.Addr]appAddr)
		s.transitIPs[nid] = peerMap
	}
	peerMap[tipr.TransitIP] = appAddr{addr: tipr.DestinationIP, app: tipr.App}
	return TransitIPResponse{}
}

func (s *server) transitIPTarget(nid tailcfg.NodeID, tip netip.Addr) netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitIPs[nid][tip].addr
}

// TransitIPRequest details a single TransitIP allocation request from a client to a
// connector.
type TransitIPRequest struct {
	// TransitIP is the intermediate destination IP that will be received at this
	// connector and will be replaced by DestinationIP when performing DNAT.
	TransitIP netip.Addr `json:"transitIP,omitzero"`

	// DestinationIP is the final destination IP that connections to the TransitIP
	// should be mapped to when performing DNAT.
	DestinationIP netip.Addr `json:"destinationIP,omitzero"`

	// App is the name of the connector application from the tailnet
	// configuration.
	App string `json:"app,omitzero"`
}

// ConnectorTransitIPRequest is the request body for a PeerAPI request to
// /connector/transit-ip and can include zero or more TransitIP allocation requests.
type ConnectorTransitIPRequest struct {
	// TransitIPs is the list of requested mappings.
	TransitIPs []TransitIPRequest `json:"transitIPs,omitempty"`
}

// TransitIPResponseCode appears in TransitIPResponse and signifies success or failure status.
type TransitIPResponseCode int

const (
	// OK indicates that the mapping was created as requested.
	OK TransitIPResponseCode = 0

	// OtherFailure indicates that the mapping failed for a reason that does not have
	// another relevant [TransitIPResponsecode].
	OtherFailure TransitIPResponseCode = 1
)

// TransitIPResponse is the response to a TransitIPRequest
type TransitIPResponse struct {
	// Code is an error code indicating success or failure of the [TransitIPRequest].
	Code TransitIPResponseCode `json:"code,omitzero"`
	// Message is an error message explaining what happened, suitable for logging but
	// not necessarily suitable for displaying in a UI to non-technical users. It
	// should be empty when [Code] is [OK].
	Message string `json:"message,omitzero"`
}

// ConnectorTransitIPResponse is the response to a ConnectorTransitIPRequest
type ConnectorTransitIPResponse struct {
	// TransitIPs is the list of outcomes for each requested mapping. Elements
	// correspond to the order of [ConnectorTransitIPRequest.TransitIPs].
	TransitIPs []TransitIPResponse `json:"transitIPs,omitempty"`
}

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

type client struct {
	mu sync.Mutex
	// map of magic IP -> (transit IP, app)
	magicIPs map[netip.Addr]appAddr
}

func (c *client) setMagicIP(magicAddr, transitAddr netip.Addr, app string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mak.Set(&c.magicIPs, magicAddr, appAddr{addr: transitAddr, app: app})
}

type server struct {
	mu sync.Mutex
	// transitIPs is a map of connector client peer NodeID -> client transitIPs that we update as connector client peers instruct us to, and then use to route traffic to its destination on behalf of connector clients.
	transitIPs map[tailcfg.NodeID]map[netip.Addr]appAddr
}
