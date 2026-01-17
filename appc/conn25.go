// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"errors"
	"net/netip"
	"os"
	"sync"

	"tailscale.com/tailcfg"
)

// // mzbs fake functions ////
func (c *Conn25) ClientTransitIPForMagicIP(magic netip.Addr) (netip.Addr, error) {
	if !magic.Is4() {
		return netip.Addr{}, errors.New("bootleg transit ip for magic ip only deals with ip4 for now")
	}
	mb := magic.As4()
	mb[0], mb[1] = 169, 254

	return netip.AddrFrom4(mb), nil
}

func (c *Conn25) ConnectorRealIPForTransitIPConnection(clientSrc, transitIP netip.Addr) (netip.Addr, error) {
	// The transitIP may have overlap on this connector, right?
	// In order to disambiguate we also need to know what client this came from.
	// And all we have in the packet is the client src IP address.
	return netip.MustParseAddr("104.16.184.241"), nil // icanhazip.com
}

func (c *Conn25) SelfIsConnector() bool {
	// We need this so that if this is a connector, the datapath can quickly look in the
	// connector flow tracking table to fast path trafffic.
	v, _ := os.LookupEnv("MZB_SELF_IS_CONNECTOR")
	return v == "true"
}

//// end mzbs fake functions ////

// Conn25 holds the developing state for the as yet nascent next generation app connector.
// There is currently (2025-12-08) no actual app connecting functionality.
type Conn25 struct {
	mu         sync.Mutex
	transitIPs map[tailcfg.NodeID]map[netip.Addr]netip.Addr
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
		tipresp := c.handleTransitIPRequest(nid, each)
		seen[each.TransitIP] = true
		resp.TransitIPs = append(resp.TransitIPs, tipresp)
	}
	return resp
}

func (c *Conn25) handleTransitIPRequest(nid tailcfg.NodeID, tipr TransitIPRequest) TransitIPResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.transitIPs == nil {
		c.transitIPs = make(map[tailcfg.NodeID]map[netip.Addr]netip.Addr)
	}
	peerMap, ok := c.transitIPs[nid]
	if !ok {
		peerMap = make(map[netip.Addr]netip.Addr)
		c.transitIPs[nid] = peerMap
	}
	peerMap[tipr.TransitIP] = tipr.DestinationIP
	return TransitIPResponse{}
}

func (c *Conn25) transitIPTarget(nid tailcfg.NodeID, tip netip.Addr) netip.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transitIPs[nid][tip]
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
