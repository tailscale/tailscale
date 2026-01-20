// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"net/netip"
	"sync"

	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/tailcfg"
)

var tsMBox = dnsmessage.MustNewName("support.tailscale.com.")

type appAddr struct {
	app  string
	addr netip.Addr
}

// Conn25 holds the developing state for the as yet nascent next generation app connector.
// There is currently (2025-12-08) no actual app connecting functionality.
type Conn25 struct {
	magicIPPool   ippool // should not be mutated
	transitIPPool ippool // should not be mutated

	mu sync.Mutex
	// map of peer -> (map of transitip -> dst ip)
	transitIPs map[tailcfg.NodeID]map[netip.Addr]netip.Addr
	// map of peer -> (map of magicip -> appAddr of dst ip)
	magicIPs map[tailcfg.NodeID]map[netip.Addr]appAddr
}

func NewConn25(magicPool, transitPool *netipx.IPSet) *Conn25 {
	return &Conn25{
		magicIPPool:   *newIPPool(magicPool),
		transitIPPool: *newIPPool(transitPool),
	}
}

func (c *Conn25) assignMagic(domain string, addr netip.Addr) (netip.Addr, error) {
	mip, err := c.magicIPPool.next()
	if err != nil {
		// TODO(fran) the pool is exhausted, what to do?
		return netip.Addr{}, err
	}
	// TODO(fran) plumb this through from somewhere
	nid := tailcfg.NodeID(1)
	// TODO(fran)
	app := "dunno? " + domain
	c.setMagicIP(nid, mip, addr, app)
	return mip, nil
}

func (c *Conn25) MapDNSResponse(buf []byte) []byte {
	// TODO(fran) should we be passing everything through (pretending we're not here)
	// or eg putting our info in SOARecords?
	// TODO(fran) does something a bit more general than this belong in the dns package somewhere?
	// how similar is it to what we do in natc (not _super_ similar), or eg sniproxy, messagecache, peerapi
	var msg dnsmessage.Message
	err := msg.Unpack(buf)
	if err != nil {
		return buf
	}

	var resolves map[string][]netip.Addr
	var addrQCount int
	for _, q := range msg.Questions {
		if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
			continue
		}
		addrQCount++
	}

	rcode := dnsmessage.RCodeSuccess
	if addrQCount > 0 && len(resolves) == 0 {
		rcode = dnsmessage.RCodeNameError
	}

	b := dnsmessage.NewBuilder(nil,
		dnsmessage.Header{
			ID:            msg.Header.ID,
			Response:      true,
			Authoritative: true,
			RCode:         rcode,
		})
	b.EnableCompression()

	if err := b.StartQuestions(); err != nil {
		return buf
	}

	for _, q := range msg.Questions {
		b.Question(q)
	}

	if err := b.StartAnswers(); err != nil {
		return buf
	}

	for _, a := range msg.Answers {
		switch a.Header.Type {
		case dnsmessage.TypeA:
			msgARecord := (a.Body).(*dnsmessage.AResource)
			ourAddr, err := c.assignMagic(a.Header.Name.String(), netip.AddrFrom4(msgARecord.A))
			if err != nil {
				return buf
			}
			if err := b.AResource(
				a.Header,
				dnsmessage.AResource{A: ourAddr.As4()},
			); err != nil {
				return buf
			}
		default:
			// TODO how to just write whatever we already have? is this it?
			body := a.Body.(*dnsmessage.UnknownResource)
			b.UnknownResource(a.Header, *body)
		}
	}

	outbs, err := b.Finish()
	if err != nil {
		return buf
	}
	return outbs
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

func (c *Conn25) setMagicIP(nid tailcfg.NodeID, magicAddr, dstAddr netip.Addr, app string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.magicIPs == nil {
		c.magicIPs = make(map[tailcfg.NodeID]map[netip.Addr]appAddr)
	}
	peerMap, ok := c.magicIPs[nid]
	if !ok {
		peerMap = make(map[netip.Addr]appAddr)
		c.magicIPs[nid] = peerMap
	}
	peerMap[magicAddr] = appAddr{addr: dstAddr, app: app}
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
