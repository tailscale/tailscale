// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"net/netip"
	"sync"

	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

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

// DatapathHandler provides methods to intercept, mangle, and filter packets
// in the datapath for app connector purposes.
type DatapathHandler interface {
	// HandleLocalTraffic intercepts traffic from the local network stack, e.g. the tun device, and
	// determines if the traffic is app connector traffic that should be forwarded to a connector,
	// or is return traffic that should be forwarded back to the originating client. Valid packets may
	// be altered, e.g. NAT, and invalid packets may be dropped.
	HandleLocalTraffic(*packet.Parsed) filter.Response

	// HandleTunnelTraffic intercepts traffic from the wireguard tunnel and determines if the traffic
	// is app connector traffic that should be forwarded to an application destination or back to the
	// local network stack. Valid packets may be altered, e.g. NAT, and invalid packets may be dropped.
	HandleTunnelTraffic(*packet.Parsed) filter.Response
}

// datapathHandler is the main implementation of DatapathHandler.
type datapathHandler struct {
	// conn25 *Conn25 perhaps
	// flowTable Flowtable perhaps
}

func NewDatpathHandler() DatapathHandler {
	return &datapathHandler{}
}

func (dh *datapathHandler) HandleLocalTraffic(p *packet.Parsed) filter.Response {
	// Connector-bound traffic.
	if dh.dstIPIsMagicIP(p) {
		return dh.processClientToConnector(p)
	}

	// Return traffic from external application.
	if dh.selfIsConnector() && dh.isConnectorReturnTraffic(p) {
		return dh.processConnectorToClient(p)
	}
	// if controller client with flow in flow table, find address for source nat. If not, forward along.

	return filter.Accept
}

func (dh *datapathHandler) HandleTunnelTraffic(p *packet.Parsed) filter.Response {
	// Return traffic from connector, source is a Transit IP.
	if dh.srcIsTransitIP(p) {
		return dh.processClientFromConnector(p)
	}

	// Outgoing traffic for an external application. Destination is Transit IP.
	if dh.selfIsConnector() && dh.dstIPIsTransitIP(p) {
		return dh.processConnectorFromClient(p)
	}
	return filter.Accept
}

// processClientToConnector consults the flow table to determine which connector to send the packet to,
// and if this is a new flow, runs the connector selection algorithm, and installs a new flow.
// If the packet is valid, we DNAT from the Magic IP to the Transit IP.
// If there is no flow or the packet is otherwise invalid, we drop the packet.
func (dh *datapathHandler) processClientToConnector(p *packet.Parsed) filter.Response {
	// TODO: implement
	// TODO: we could do magic IP validation here as well

	// This is just an example of how to do the NAT, when we need it.
	transitIP := netip.AddrFrom4([4]byte{169, 254, 100, 1})
	checksum.UpdateDstAddr(p, transitIP)

	return filter.Drop
}

// processConnectorToClient consults the flow table on a connector to determine which client
// to send the return traffic to.
// If the packet is valid, we SNAT the external application IP to the Transit IP.
// If there is no flow or the packet is otherwise invalid, we drop the packet.
func (dh *datapathHandler) processConnectorToClient(p *packet.Parsed) filter.Response {
	// TODO: implement
	return filter.Drop
}

// processClientFromConnector consults the flow table to validate that the packet should
// be forwarded back to the local network stack.
// We SNAT the Transit IP back to the Magic IP.
// If there is no flow or the packet is otherwise invalid, we drop the packet.
func (dh *datapathHandler) processClientFromConnector(p *packet.Parsed) filter.Response {
	// TODO: implement
	return filter.Drop
}

// processConnectorFromClient consults the flow table to see if this packet is part of
// an existing outbound flow to an application, or a new flow should be installed.
// If the packet is valid, we DNAT from the Transit IP to the external application IP.
// If there is no flow or the packet is otherwise invalid, we drop the packet.
func (dh *datapathHandler) processConnectorFromClient(p *packet.Parsed) filter.Response {
	// TODO: implement
	return filter.Drop
}

// dstIPIsMagicIP returns whether the destination IP address in p is Magic IP,
// which could indicate interesting traffic for outbound traffic from a client to a connector.
func (dh *datapathHandler) dstIPIsMagicIP(p *packet.Parsed) bool {
	// TODO: implement
	// TODO: we could do magic IP validation here as well
	return false
}

func (dh *datapathHandler) srcIsTransitIP(p *packet.Parsed) bool {
	// TODO: implement
	return false
}

func (dh *datapathHandler) dstIPIsTransitIP(p *packet.Parsed) bool {
	// TODO: implement
	return false
}

// selfIsConnector returns whether this client is running on an app connector.
func (dh *datapathHandler) selfIsConnector() bool {
	// TODO: implement
	return false
}

func (dh *datapathHandler) isConnectorReturnTraffic(p *packet.Parsed) bool {
	// TODO: implement
	return false
}
