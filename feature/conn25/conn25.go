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
	"maps"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
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
	"tailscale.com/types/views"
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
			conn:    newConn25(logger.WithPrefix(logf, "conn25: ")),
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
	conn    *Conn25            // safe for concurrent access and only set at creation
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
	resp := e.conn.handleConnectorTransitIPRequest(h.Peer().ID(), req)
	bs, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
	w.Write(bs)
}

func (e *extension) onSelfChange(selfNode tailcfg.NodeView) {
	err := e.conn.reconfig(selfNode)
	if err != nil {
		e.conn.client.logf("error during Reconfig onSelfChange", err)
		return
	}

	if e.conn.isConfigured() {
		err = e.registerDNSHook()
	} else {
		err = e.unregisterDNSHook()
	}
	if err != nil {
		e.conn.client.logf("error managing DNS hook onSelfChange", err)
	}
}

func (e *extension) registerDNSHook() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.isDNSHookRegistered {
		return nil
	}
	err := e.setDNSHookLocked(e.conn.mapDNSResponse)
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
		return errors.New("Couldn't get DNSManager from sys")
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
	client *client
	server *server
}

func (c *Conn25) isConfigured() bool {
	return c.client.isConfigured()
}

func newConn25(logf logger.Logf) *Conn25 {
	c := &Conn25{
		client: &client{logf: logf},
		server: &server{logf: logf},
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
	if err := c.client.reconfig(selfNode); err != nil {
		return err
	}
	if err := c.server.reconfig(selfNode); err != nil {
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

// configSrc is the parts of the selfNode NodeView that affect
// the state of config. Used to check if a reconfig with a selfNode
// will change the state of config, to avoid unnecessary reconfigs.
type configSrc struct {
	apps []tailcfg.RawMessage
	tags []string
}

func (cs *configSrc) matches(other *configSrc) bool {
	return reflect.DeepEqual(cs, other)
}

func configSrcFromNodeView(n tailcfg.NodeView) *configSrc {
	return &configSrc{
		apps: n.CapMap().Get(AppConnectorsExperimentalAttrName).AsSlice(),
		tags: n.Tags().AsSlice(),
	}
}

// config holds the config from the policy and lookups derived from that.
// config is not safe for concurrent use.
type config struct {
	src               *configSrc
	apps              []appctype.Conn25Attr
	appsByDomain      map[string][]string
	selfRoutedDomains set.Set[string]
}

func (c *config) reconfig(selfNode tailcfg.NodeView) (bool, error) {
	cfgSrc := configSrcFromNodeView(selfNode)
	if cfgSrc.matches(c.src) {
		return false, nil
	}
	return c.reconfigFromCfgSrc(cfgSrc)
}

func (c *config) reconfigFromCfgSrc(src *configSrc) (bool, error) {
	msv := views.MapSliceOf(map[tailcfg.NodeCapability][]tailcfg.RawMessage{
		AppConnectorsExperimentalAttrName: src.apps,
	})
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.Conn25Attr](msv, AppConnectorsExperimentalAttrName)
	if err != nil {
		return true, err
	}

	selfTags := set.SetOf(src.tags)

	c.src = src
	c.apps = apps

	c.appsByDomain = map[string][]string{}
	c.selfRoutedDomains = set.Set[string]{}
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
				return true, err
			}
			key := fqdn.WithTrailingDot()
			mak.Set(&c.appsByDomain, key, append(c.appsByDomain[key], app.Name))
			if selfMatchesTags {
				c.selfRoutedDomains.Add(key)
			}
		}
	}
	return true, nil
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
	return c.config.src != nil
}

func (c *client) reconfig(selfNode tailcfg.NodeView) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	updated, err := c.config.reconfig(selfNode)
	if !updated || err != nil {
		return err
	}
	c.logf("client reconfigured, domains: %v", slices.Collect(maps.Keys(c.config.appsByDomain)))

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

func (c *client) reserveAddresses(domain string, dst netip.Addr) (connection, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	appNames, ok := c.config.appsByDomain[domain]
	// Is this domain routed by connectors?
	if !ok || len(appNames) == 0 {
		return connection{}, nil
	}
	// We don't ask another connector to route (and so don't reserve addresses for)
	// domains that we ourselves route as a connector.
	if c.config.selfRoutedDomains.Contains(domain) {
		return connection{}, nil
	}
	// only reserve for first app
	app := appNames[0]
	mip, err := c.magicIPPool.next()
	if err != nil {
		return connection{}, err
	}
	tip, err := c.transitIPPool.next()
	if err != nil {
		return connection{}, err
	}
	connection := connection{
		dst:     dst,
		magic:   mip,
		transit: tip,
		app:     app,
	}
	c.logf("assigning magic ip for domain: %s, app: %s, %v", domain, app, mip)
	return connection, nil
}

func (c *client) enqueueAddressAssignment(conn connection) {
	c.setMagicIP(conn.magic, conn.transit, conn.app)
	// TODO(fran) 2026-02-03 asynchronously send peerapi req to connector to
	// allocate these addresses for us.
}

func (c *client) mapDNSResponse(buf []byte) []byte {
	var msg dnsmessage.Message
	err := msg.Unpack(buf)
	if err != nil {
		return buf
	}

	for _, a := range msg.Answers {
		// TODO(fran) AAAA?
		switch a.Header.Type {
		case dnsmessage.TypeA:
			msgARecord := (a.Body).(*dnsmessage.AResource)
			domain := a.Header.Name.String()
			dst := netip.AddrFrom4(msgARecord.A)
			connection, err := c.reserveAddresses(domain, dst)
			if err != nil {
				// TODO(fran) log
				return buf
			}
			if !connection.isValid() {
				return buf
			}
			c.enqueueAddressAssignment(connection)
		}
	}

	// TODO(fran) 2026-01-21 return a dns response with addresses
	// swapped out for the magic IPs to make conn25 work.
	return buf
}

type server struct {
	logf logger.Logf

	mu sync.Mutex // protects the fields below
	// transitIPs is a map of connector client peer NodeID -> client transitIPs that we update as connector client peers instruct us to, and then use to route traffic to its destination on behalf of connector clients.
	transitIPs map[tailcfg.NodeID]map[netip.Addr]appAddr
	config     config
}

func (s *server) reconfig(selfNode tailcfg.NodeView) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.config.reconfig(selfNode)
	return err
}

type connection struct {
	dst     netip.Addr
	magic   netip.Addr
	transit netip.Addr
	app     string
}

func (c connection) isValid() bool {
	return c.dst.IsValid()
}
