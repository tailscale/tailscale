package appc

import (
	"net/netip"
	"sync"

	"tailscale.com/tailcfg"
)

type Conn25 struct {
	mu           sync.Mutex
	transitIPMap map[tailcfg.NodeID]map[netip.Addr]netip.Addr
}

func (c *Conn25) HandleConnectorTransitIPRequest(nid tailcfg.NodeID, ctipr ConnectorTransitIPRequest) ConnectorTransitIPResponse {
	resp := ConnectorTransitIPResponse{}
	for _, each := range ctipr.TransitIPs {
		tipresp := c.handleTransitIPRequest(nid, each)
		resp.TransitIPs = append(resp.TransitIPs, tipresp)
	}
	return resp
}

func (c *Conn25) handleTransitIPRequest(nid tailcfg.NodeID, tipr TransitIPRequest) TransitIPResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.transitIPMap == nil {
		c.transitIPMap = make(map[tailcfg.NodeID]map[netip.Addr]netip.Addr)
	}
	peerMap, ok := c.transitIPMap[nid]
	if !ok {
		peerMap = make(map[netip.Addr]netip.Addr)
		c.transitIPMap[nid] = peerMap
	}
	peerMap[tipr.TransitIP] = tipr.DestinationIP
	return TransitIPResponse{}
}

// TransitIPRequest details a single TransitIP allocation request from a client to a
// connector.
type TransitIPRequest struct {
	// Mapping details

	// TransitIP is the intermediate destination IP that will be received at this
	// connector and will be replaced by DestinationIP when performing DNAT. The
	// TransitIP is specific to the peer making this request and must be within the
	// tailnet's TransitIP range.
	// If the connector already has a mapping for this TransitIP from this client, it
	// will be replaced with the new mapping specified here. It is an error to request
	// the same TransitIP more than once in the same [ConnectorTransitIPRequest].
	TransitIP netip.Addr `json:"transitIP,omitzero"`
	// DestinationIP is the final destination IP that connections to the TransitIP
	// should be mapped to when performing DNAT.
	// If the connector already has a mapping for this DestinationIP in the context of
	// this client and App, then the connector may immediately expire the old mapping.
	DestinationIP netip.Addr `json:"destinationIP,omitzero"`
	// AppName is the name of the connector application from the tailnet
	// configuration, as listed in [appctype.AppConnectorAttr.Name].
	App string `json:"app,omitzero"`

	// Proof of destination IP (optional)

	// FQDNs is an optional list of FQDNs that have previously resolved to the
	// requested destination IP. If the connector's destination IP cache does not
	// currently indicate that the destination IP applies to the app, then the
	// connector may attempt DNS resolution to confirm the destination IP instead of
	// rejecting the request.
	FQDNs []string `json:"fqdns,omitempty"`
}

// ConnectorTransitIPRequest is the request body for a PeerAPI request to
// /connector/transit-ip and can include zero or more TransitIP allocation requests.
type ConnectorTransitIPRequest struct {
	// Clear is set when the client wishes to flush the connector's TransitIP
	// configuration for this client. The connector may ignore Clear, for it is simply
	// a hint to accelerate cache expiry. Clients are expected to set this on the
	// first request to a particular connector after client start in order to clear
	// lingering mappings from a prior instance.
	Clear bool `json:"clear,omitzero"`
	// TransitIPs is the list of requested mappings.
	TransitIPs []TransitIPRequest `json:"transitIPs,omitempty"`
}
type TransitIPResponseCode int

const (
	// OK indicates that the mapping was created as requested.
	OK TransitIPResponseCode = 0
	// OtherFailure indicates that the mapping failed for a reason that does not have
	// another relevant [TransitIPResponsecode].
	OtherFailure TransitIPResponseCode = 1
	// MissingProof indicates that the mapping failed because the connector has not
	// seen sufficient proof (via local cache or the Proof section of
	// [TransitIPRequest]) that the requested destination IP applies to the specified
	// App. The request can be retried after supplying additional proof.
	MissingProof TransitIPResponseCode = 2
)

type TransitIPResponse struct {
	// Code is an error code indicating success or failure of the [TransitIPRequest].
	Code TransitIPResponseCode `json:"code,omitzero"`
	// Message is an error message explaining what happened, suitable for logging but
	// not necessarily suitable for displaying in a UI to non-technical users. It
	// should be empty when [Code] is [OK].
	Message string `json:"message,omitzero"`
}
type ConnectorTransitIPResponse struct {
	// Clear is set when the connector wishes to flush the client's TransitIP
	// configuration for this connector. The client may ignore Clear, for it is simply
	// a hint to accelerate cache expiry. Connectors are expected to set this on the
	// first response to a particular client after connector start in order to clear
	// lingering mappings from a prior instance.
	Clear bool `json:"clear,omitzero"`
	// TransitIPs is the list of outcomes for each requested mapping. Elements
	// correspond to the order of [ConnectorTransitIPRequest.TransitIPs].
	TransitIPs []TransitIPResponse `json:"transitIPs,omitempty"`
}
