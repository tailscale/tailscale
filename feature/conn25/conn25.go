// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package conn25 registers the conn25 feature and implements its associated ipnext.Extension.
// conn25 will be an app connector like feature that routes traffic for configured domains via
// connector devices and avoids the "too many routes" pitfall of app connector. It is currently
// (2026-02-04) some peer API routes for clients to tell connectors about their desired routing.
package conn25

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/feature"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/dns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
)

// featureName is the name of the feature implemented by this package.
// It is also the [extension] name and the log prefix.
const featureName = "conn25"

func init() {
	feature.Register(featureName)
	newExtension := func(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
		e := &extension{
			conn25:  newConn25(logger.WithPrefix(logf, "conn25: ")),
			backend: sb,
		}
		return e, nil
	}
	ipnext.RegisterExtension(featureName, newExtension)
	ipnlocal.RegisterPeerAPIHandler("/v0/connector/transit-ip", handleConnectorTransitIP)
}

func handleConnectorTransitIP(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	e, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		http.Error(w, "miswired", http.StatusInternalServerError)
		return
	}
	e.handleConnectorTransitIP(h, w, r)
}

// extension is an [ipnext.Extension] managing the connector on platforms
// that import this package.
type extension struct {
	conn25  *Conn25            // safe for concurrent access and only set at creation
	backend ipnext.SafeBackend // safe for concurrent access and only set at creation

	mu                  sync.Mutex // protects the fields below
	isDNSHookRegistered bool
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string {
	return featureName
}

// Init implements [ipnext.Extension].
func (e *extension) Init(host ipnext.Host) error {
	host.Hooks().OnSelfChange.Add(e.onSelfChange)
	return nil
}

// Shutdown implements [ipnlocal.Extension].
func (e *extension) Shutdown() error {
	return nil
}

func (e *extension) handleConnectorTransitIP(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	const maxBodyBytes = 1024 * 1024
	defer r.Body.Close()
	if r.Method != "POST" {
		http.Error(w, "Method should be POST", http.StatusMethodNotAllowed)
		return
	}
	var req ConnectorTransitIPRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes+1)).Decode(&req)
	if err != nil {
		http.Error(w, "Error decoding JSON", http.StatusBadRequest)
		return
	}
	resp := e.conn25.handleConnectorTransitIPRequest(h.Peer().ID(), req)
	bs, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
	w.Write(bs)
}

func (e *extension) onSelfChange(selfNode tailcfg.NodeView) {
	err := e.conn25.reconfig(selfNode)
	if err != nil {
		e.conn25.client.logf("error during Reconfig onSelfChange: %v", err)
		return
	}

	if e.conn25.isConfigured() {
		err = e.registerDNSHook()
	} else {
		err = e.unregisterDNSHook()
	}
	if err != nil {
		e.conn25.client.logf("error managing DNS hook onSelfChange: %v", err)
	}
}

func (e *extension) registerDNSHook() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isDNSHookRegistered {
		return nil
	}
	err := e.setDNSHookLocked(e.conn25.mapDNSResponse)
	if err == nil {
		e.isDNSHookRegistered = true
	}
	return err
}

func (e *extension) unregisterDNSHook() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.isDNSHookRegistered {
		return nil
	}
	err := e.setDNSHookLocked(nil)
	if err == nil {
		e.isDNSHookRegistered = false
	}
	return err
}

func (e *extension) setDNSHookLocked(fx dns.ResponseMapper) error {
	dnsManager, ok := e.backend.Sys().DNSManager.GetOK()
	if !ok || dnsManager == nil {
		return errors.New("couldn't get DNSManager from sys")
	}
	dnsManager.SetQueryResponseMapper(fx)
	return nil
}

type appAddr struct {
	app  string
	addr netip.Addr
}

// Conn25 holds state for routing traffic for a domain via a connector.
type Conn25 struct {
	client    *client
	connector *connector
}

func (c *Conn25) isConfigured() bool {
	return c.client.isConfigured()
}

func newConn25(logf logger.Logf) *Conn25 {
	c := &Conn25{
		client:    &client{logf: logf},
		connector: &connector{logf: logf},
	}
	return c
}

func ipSetFromIPRanges(rs []netipx.IPRange) (*netipx.IPSet, error) {
	b := &netipx.IPSetBuilder{}
	for _, r := range rs {
		b.AddRange(r)
	}
	return b.IPSet()
}

func (c *Conn25) reconfig(selfNode tailcfg.NodeView) error {
	cfg, err := configFromNodeView(selfNode)
	if err != nil {
		return err
	}
	if err := c.client.reconfig(cfg); err != nil {
		return err
	}
	if err := c.connector.reconfig(cfg); err != nil {
		return err
	}
	return nil
}

// mapDNSResponse parses and inspects the DNS response, and uses the
// contents to assign addresses for connecting. It does not yet modify
// the response.
func (c *Conn25) mapDNSResponse(buf []byte) []byte {
	return c.client.mapDNSResponse(buf)
}

const dupeTransitIPMessage = "Duplicate transit address in ConnectorTransitIPRequest"

// handleConnectorTransitIPRequest creates a ConnectorTransitIPResponse in response to a ConnectorTransitIPRequest.
// It updates the connectors mapping of TransitIP->DestinationIP per peer (tailcfg.NodeID).
// If a peer has stored this mapping in the connector Conn25 will route traffic to TransitIPs to DestinationIPs for that peer.
func (c *Conn25) handleConnectorTransitIPRequest(nid tailcfg.NodeID, ctipr ConnectorTransitIPRequest) ConnectorTransitIPResponse {
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
		tipresp := c.connector.handleTransitIPRequest(nid, each)
		seen[each.TransitIP] = true
		resp.TransitIPs = append(resp.TransitIPs, tipresp)
	}
	return resp
}

func (s *connector) handleTransitIPRequest(nid tailcfg.NodeID, tipr TransitIPRequest) TransitIPResponse {
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

func (s *connector) transitIPTarget(nid tailcfg.NodeID, tip netip.Addr) netip.Addr {
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

// config holds the config from the policy and lookups derived from that.
// config is not safe for concurrent use.
type config struct {
	isConfigured      bool
	apps              []appctype.Conn25Attr
	appsByDomain      map[string][]string
	selfRoutedDomains set.Set[string]
}

func configFromNodeView(n tailcfg.NodeView) (config, error) {
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.Conn25Attr](n.CapMap(), AppConnectorsExperimentalAttrName)
	if err != nil {
		return config{}, err
	}
	if len(apps) == 0 {
		return config{}, nil
	}
	selfTags := set.SetOf(n.Tags().AsSlice())
	cfg := config{
		isConfigured:      true,
		apps:              apps,
		appsByDomain:      map[string][]string{},
		selfRoutedDomains: set.Set[string]{},
	}
	for _, app := range apps {
		selfMatchesTags := false
		for _, tag := range app.Connectors {
			if selfTags.Contains(tag) {
				selfMatchesTags = true
				break
			}
		}
		for _, d := range app.Domains {
			fqdn, err := dnsname.ToFQDN(d)
			if err != nil {
				return config{}, err
			}
			key := fqdn.WithTrailingDot()
			mak.Set(&cfg.appsByDomain, key, append(cfg.appsByDomain[key], app.Name))
			if selfMatchesTags {
				cfg.selfRoutedDomains.Add(key)
			}
		}
	}
	return cfg, nil
}

// client performs the conn25 functionality for clients of connectors
// It allocates magic and transit IP addresses and communicates them with
// connectors.
// It's safe for concurrent use.
type client struct {
	logf logger.Logf

	mu            sync.Mutex // protects the fields below
	magicIPPool   *ippool
	transitIPPool *ippool
	// map of magic IP -> (transit IP, app)
	magicIPs map[netip.Addr]appAddr
	config   config
}

func (c *client) isConfigured() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.config.isConfigured
}

func (c *client) reconfig(newCfg config) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.config = newCfg

	// TODO(fran) this is not the correct way to manage the pools and changes to the pools.
	// We probably want to:
	//  * check the pools haven't changed
	//  * reset the whole connector if the pools change? or just if they've changed to exclude
	//    addresses we have in use?
	//  * have config separate from the apps for this (rather than multiple potentially conflicting places)
	// but this works while we are just getting started here.
	for _, app := range c.config.apps {
		if c.magicIPPool != nil { // just take the first config and never reconfig
			break
		}
		if app.MagicIPPool == nil {
			continue
		}
		mipp, err := ipSetFromIPRanges(app.MagicIPPool)
		if err != nil {
			return err
		}
		tipp, err := ipSetFromIPRanges(app.TransitIPPool)
		if err != nil {
			return err
		}
		c.magicIPPool = newIPPool(mipp)
		c.transitIPPool = newIPPool(tipp)
	}
	return nil
}

func (c *client) setMagicIP(magicAddr, transitAddr netip.Addr, app string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	mak.Set(&c.magicIPs, magicAddr, appAddr{addr: transitAddr, app: app})
}

func (c *client) isConnectorDomain(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	appNames, ok := c.config.appsByDomain[domain]
	return ok && len(appNames) > 0
}

// reserveAddresses tries to make an assignment of addrs from the address pools
// for this domain+dst address, so that this client can use conn25 connectors.
// It checks that this domain should be routed and that this client is not itself a connector for the domain
// and generally if it is valid to make the assignment.
func (c *client) reserveAddresses(domain string, dst netip.Addr) (addrs, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	appNames, _ := c.config.appsByDomain[domain]
	// only reserve for first app
	app := appNames[0]
	mip, err := c.magicIPPool.next()
	if err != nil {
		return addrs{}, err
	}
	tip, err := c.transitIPPool.next()
	if err != nil {
		return addrs{}, err
	}
	addrs := addrs{
		dst:     dst,
		magic:   mip,
		transit: tip,
		app:     app,
	}
	return addrs, nil
}

func (c *client) enqueueAddressAssignment(addrs addrs) {
	c.setMagicIP(addrs.magic, addrs.transit, addrs.app)
	// TODO(fran) 2026-02-03 asynchronously send peerapi req to connector to
	// allocate these addresses for us.
}

func (c *client) mapDNSResponse(buf []byte) []byte {
	var p dnsmessage.Parser
	if _, err := p.Start(buf); err != nil {
		c.logf("error parsing dns response: %v", err)
		return buf
	}
	if err := p.SkipAllQuestions(); err != nil {
		c.logf("error parsing dns response: %v", err)
		return buf
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			c.logf("error parsing dns response: %v", err)
			return buf
		}

		if h.Class != dnsmessage.ClassINET {
			if err := p.SkipAnswer(); err != nil {
				c.logf("error parsing dns response: %v", err)
				return buf
			}
			continue
		}

		switch h.Type {
		case dnsmessage.TypeA:
			domain := strings.ToLower(h.Name.String())
			if len(domain) == 0 || !c.isConnectorDomain(domain) {
				if err := p.SkipAnswer(); err != nil {
					c.logf("error parsing dns response: %v", err)
					return buf
				}
				continue
			}
			r, err := p.AResource()
			if err != nil {
				c.logf("error parsing dns response: %v", err)
				return buf
			}
			addrs, err := c.reserveAddresses(domain, netip.AddrFrom4(r.A))
			if err != nil {
				c.logf("error assigning connector addresses: %v", err)
				return buf
			}
			if !addrs.isValid() {
				c.logf("assigned connector addresses unexpectedly empty: %v", err)
				return buf
			}
			c.enqueueAddressAssignment(addrs)
		default:
			if err := p.SkipAnswer(); err != nil {
				c.logf("error parsing dns response: %v", err)
				return buf
			}
			continue
		}
	}

	// TODO(fran) 2026-01-21 return a dns response with addresses
	// swapped out for the magic IPs to make conn25 work.
	return buf
}

type connector struct {
	logf logger.Logf

	mu sync.Mutex // protects the fields below
	// transitIPs is a map of connector client peer NodeID -> client transitIPs that we update as connector client peers instruct us to, and then use to route traffic to its destination on behalf of connector clients.
	transitIPs map[tailcfg.NodeID]map[netip.Addr]appAddr
	config     config
}

func (s *connector) reconfig(newCfg config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = newCfg
	return nil
}

type addrs struct {
	dst     netip.Addr
	magic   netip.Addr
	transit netip.Addr
	app     string
}

func (c addrs) isValid() bool {
	return c.dst.IsValid()
}
