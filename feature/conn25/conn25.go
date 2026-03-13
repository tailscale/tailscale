// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package conn25 registers the conn25 feature and implements its associated ipnext.Extension.
// conn25 will be an app connector like feature that routes traffic for configured domains via
// connector devices and avoids the "too many routes" pitfall of app connector. It is currently
// (2026-02-04) some peer API routes for clients to tell connectors about their desired routing.
package conn25

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"sync"

	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc"
	"tailscale.com/feature"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/dns"
	"tailscale.com/net/tsaddr"
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

const maxBodyBytes = 1024 * 1024

// jsonDecode decodes all of a io.ReadCloser (eg an http.Request Body) into one pointer with best practices.
// It limits the size of bytes it will read.
// It either decodes all of the bytes into the pointer, or errors (unlike json.Decoder.Decode).
// It closes the ReadCloser after reading.
func jsonDecode(target any, rc io.ReadCloser) error {
	defer rc.Close()
	respBs, err := io.ReadAll(io.LimitReader(rc, maxBodyBytes+1))
	if err != nil {
		return err
	}
	err = json.Unmarshal(respBs, &target)
	return err
}

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, func(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
		return &extension{
			conn25:  newConn25(logger.WithPrefix(logf, "conn25: ")),
			backend: sb,
		}, nil
	})
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

	host      ipnext.Host             // set in Init, read-only after
	ctxCancel context.CancelCauseFunc // cancels sendLoop goroutine

	mu                  sync.Mutex // protects the fields below
	isDNSHookRegistered bool
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string {
	return featureName
}

// Init implements [ipnext.Extension].
func (e *extension) Init(host ipnext.Host) error {
	//Init only once
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctxCancel != nil {
		return nil
	}
	e.host = host
	host.Hooks().OnSelfChange.Add(e.onSelfChange)
	ctx, cancel := context.WithCancelCause(context.Background())
	e.ctxCancel = cancel
	go e.sendLoop(ctx)
	return nil
}

// Shutdown implements [ipnlocal.Extension].
func (e *extension) Shutdown() error {
	if e.ctxCancel != nil {
		e.ctxCancel(errors.New("extension shutdown"))
	}
	if e.conn25 != nil {
		close(e.conn25.client.addrsCh)
	}
	return nil
}

func (e *extension) handleConnectorTransitIP(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
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
	resp := e.conn25.handleConnectorTransitIPRequest(h.Peer(), req)
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
		client: &client{
			logf:    logf,
			addrsCh: make(chan addrs, 64),
		},
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
const noMatchingPeerIPFamilyMessage = "No peer IP found with matching IP family"
const addrFamilyMismatchMessage = "Transit and Destination addresses must have matching IP family"
const unknownAppNameMessage = "The App name in the request does not match a configured App"

// handleConnectorTransitIPRequest creates a ConnectorTransitIPResponse in response
// to a ConnectorTransitIPRequest. It updates the connectors mapping of
// TransitIP->DestinationIP per peer (using the Peer's IP that matches the address
// family of the transitIP). If a peer has stored this mapping in the connector,
// Conn25 will route traffic to TransitIPs to DestinationIPs for that peer.
func (c *Conn25) handleConnectorTransitIPRequest(n tailcfg.NodeView, ctipr ConnectorTransitIPRequest) ConnectorTransitIPResponse {
	var peerIPv4, peerIPv6 netip.Addr
	for _, ip := range n.Addresses().All() {
		if !ip.IsSingleIP() || !tsaddr.IsTailscaleIP(ip.Addr()) {
			continue
		}
		if ip.Addr().Is4() && !peerIPv4.IsValid() {
			peerIPv4 = ip.Addr()
		} else if ip.Addr().Is6() && !peerIPv6.IsValid() {
			peerIPv6 = ip.Addr()
		}
	}

	resp := ConnectorTransitIPResponse{}
	seen := map[netip.Addr]bool{}
	for _, each := range ctipr.TransitIPs {
		if seen[each.TransitIP] {
			resp.TransitIPs = append(resp.TransitIPs, TransitIPResponse{
				Code:    DuplicateTransitIP,
				Message: dupeTransitIPMessage,
			})
			c.connector.logf("[Unexpected] peer attempt to map a transit IP reused a transitIP: node: %s, IP: %v",
				n.StableID(), each.TransitIP)
			continue
		}
		tipresp := c.connector.handleTransitIPRequest(n, peerIPv4, peerIPv6, each)
		seen[each.TransitIP] = true
		resp.TransitIPs = append(resp.TransitIPs, tipresp)
	}
	return resp
}

func (s *connector) handleTransitIPRequest(n tailcfg.NodeView, peerV4 netip.Addr, peerV6 netip.Addr, tipr TransitIPRequest) TransitIPResponse {
	if tipr.TransitIP.Is4() != tipr.DestinationIP.Is4() {
		s.logf("[Unexpected] peer attempt to map a transit IP to dest IP did not have matching families: node: %s, tIPv4: %v dIPv4: %v",
			n.StableID(), tipr.TransitIP.Is4(), tipr.DestinationIP.Is4())
		return TransitIPResponse{Code: AddrFamilyMismatch, Message: addrFamilyMismatchMessage}
	}

	// Datapath lookups only have access to the peer IP, and that will match the family
	// of the transit IP, so we need to store v4 and v6 mappings separately.
	var peerAddr netip.Addr
	if tipr.TransitIP.Is4() {
		peerAddr = peerV4
	} else {
		peerAddr = peerV6
	}

	// If we couldn't find a matching family, return an error.
	if !peerAddr.IsValid() {
		s.logf("[Unexpected] peer attempt to map a transit IP did not have a matching address family: node: %s, IPv4: %v",
			n.StableID(), tipr.TransitIP.Is4())
		return TransitIPResponse{NoMatchingPeerIPFamily, noMatchingPeerIPFamilyMessage}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.config.appsByName[tipr.App]; !ok {
		s.logf("[Unexpected] peer attempt to map a transit IP referenced unknown app: node: %s, app: %q",
			n.StableID(), tipr.App)
		return TransitIPResponse{Code: UnknownAppName, Message: unknownAppNameMessage}
	}

	if s.transitIPs == nil {
		s.transitIPs = make(map[netip.Addr]map[netip.Addr]appAddr)
	}
	peerMap, ok := s.transitIPs[peerAddr]
	if !ok {
		peerMap = make(map[netip.Addr]appAddr)
		s.transitIPs[peerAddr] = peerMap
	}
	peerMap[tipr.TransitIP] = appAddr{addr: tipr.DestinationIP, app: tipr.App}
	return TransitIPResponse{}
}

func (s *connector) transitIPTarget(peerIP, tip netip.Addr) netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.transitIPs[peerIP][tip].addr
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
	// another relevant [TransitIPResponseCode].
	OtherFailure TransitIPResponseCode = 1

	// DuplicateTransitIP indicates that the same transit address appeared more than
	// once in a [ConnectorTransitIPRequest].
	DuplicateTransitIP TransitIPResponseCode = 2

	// NoMatchingPeerIPFamily indicates that the peer did not have an associated
	// IP with the same family as transit IP being registered.
	NoMatchingPeerIPFamily = 3

	// AddrFamilyMismatch indicates that the transit IP and destination IP addresses
	// do not belong to the same IP family.
	AddrFamilyMismatch = 4

	// UnknownAppName indicates that the connector is not configured to handle requests
	// for the App name that was specified in the request.
	UnknownAppName = 5
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
	appsByName        map[string]appctype.Conn25Attr
	appNamesByDomain  map[dnsname.FQDN][]string
	selfRoutedDomains set.Set[dnsname.FQDN]
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
		appsByName:        map[string]appctype.Conn25Attr{},
		appNamesByDomain:  map[dnsname.FQDN][]string{},
		selfRoutedDomains: set.Set[dnsname.FQDN]{},
	}
	for _, app := range apps {
		selfMatchesTags := slices.ContainsFunc(app.Connectors, selfTags.Contains)
		for _, d := range app.Domains {
			fqdn, err := dnsname.ToFQDN(d)
			if err != nil {
				return config{}, err
			}
			mak.Set(&cfg.appNamesByDomain, fqdn, append(cfg.appNamesByDomain[fqdn], app.Name))
			if selfMatchesTags {
				cfg.selfRoutedDomains.Add(fqdn)
			}
		}
		mak.Set(&cfg.appsByName, app.Name, app)
	}
	return cfg, nil
}

// client performs the conn25 functionality for clients of connectors
// It allocates magic and transit IP addresses and communicates them with
// connectors.
// It's safe for concurrent use.
type client struct {
	logf    logger.Logf
	addrsCh chan addrs

	mu            sync.Mutex // protects the fields below
	magicIPPool   *ippool
	transitIPPool *ippool
	assignments   addrAssignments
	config        config
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

func (c *client) isConnectorDomain(domain dnsname.FQDN) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	appNames, ok := c.config.appNamesByDomain[domain]
	return ok && len(appNames) > 0
}

// reserveAddresses tries to make an assignment of addrs from the address pools
// for this domain+dst address, so that this client can use conn25 connectors.
// It checks that this domain should be routed and that this client is not itself a connector for the domain
// and generally if it is valid to make the assignment.
func (c *client) reserveAddresses(domain dnsname.FQDN, dst netip.Addr) (addrs, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.assignments.lookupByDomainDst(domain, dst); ok {
		return existing, nil
	}
	appNames, _ := c.config.appNamesByDomain[domain]
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
	as := addrs{
		dst:     dst,
		magic:   mip,
		transit: tip,
		app:     app,
		domain:  domain,
	}
	if err := c.assignments.insert(as); err != nil {
		return addrs{}, err
	}
	err = c.enqueueAddressAssignment(as)
	if err != nil {
		return addrs{}, err
	}
	return as, nil
}

func (e *extension) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case as := <-e.conn25.client.addrsCh:
			if err := e.sendAddressAssignment(ctx, as); err != nil {
				e.conn25.client.logf("error sending transit IP assignment (app: %s, mip: %v, src: %v): %v", as.app, as.magic, as.dst, err)
			}
		}
	}
}

func (c *client) enqueueAddressAssignment(addrs addrs) error {
	select {
	// TODO(fran) investigate the value of waiting for multiple addresses and sending them
	// in one ConnectorTransitIPRequest
	case c.addrsCh <- addrs:
		return nil
	default:
		c.logf("address assignment queue full, dropping transit assignment for %v", addrs.domain)
		return errors.New("queue full")
	}
}

func makePeerAPIReq(ctx context.Context, httpClient *http.Client, urlBase string, as addrs) error {
	url := urlBase + "/v0/connector/transit-ip"

	reqBody := ConnectorTransitIPRequest{
		TransitIPs: []TransitIPRequest{{
			TransitIP:     as.transit,
			DestinationIP: as.dst,
			App:           as.app,
		}},
	}
	bs, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bs))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("connector returned HTTP %d", resp.StatusCode)
	}

	var respBody ConnectorTransitIPResponse
	err = jsonDecode(&respBody, resp.Body)
	if err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	if len(respBody.TransitIPs) > 0 && respBody.TransitIPs[0].Code != OK {
		return fmt.Errorf("connector error: %s", respBody.TransitIPs[0].Message)
	}
	return nil
}

func (e *extension) sendAddressAssignment(ctx context.Context, as addrs) error {
	app, ok := e.conn25.client.config.appsByName[as.app]
	if !ok {
		e.conn25.client.logf("App not found for app: %s (domain: %s)", as.app, as.domain)
		return errors.New("app not found")
	}

	nb := e.host.NodeBackend()
	peers := appc.PickConnector(nb, app)
	var urlBase string
	for _, p := range peers {
		urlBase = nb.PeerAPIBase(p)
		if urlBase != "" {
			break
		}
	}
	if urlBase == "" {
		return errors.New("no connector peer found to handle address assignment")
	}
	client := e.backend.Sys().Dialer.Get().PeerAPIHTTPClient()
	return makePeerAPIReq(ctx, client, urlBase, as)
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
			domain, err := dnsname.ToFQDN(h.Name.String())
			if err != nil {
				c.logf("bad dnsname: %v", err)
				return buf
			}
			if !c.isConnectorDomain(domain) {
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
	// transitIPs is a map of connector client peer IP -> client transitIPs that we update as connector client peers instruct us to, and then use to route traffic to its destination on behalf of connector clients.
	// Note that each peer could potentially have two maps: one for its IPv4 address, and one for its IPv6 address. The transit IPs map for a given peer IP will contain transit IPs of the same family as the peer's IP.
	transitIPs map[netip.Addr]map[netip.Addr]appAddr
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
	domain  dnsname.FQDN
	app     string
}

func (c addrs) isValid() bool {
	return c.dst.IsValid()
}

// domainDst is a key for looking up an existing address assignment by the
// DNS response domain and destination IP pair.
type domainDst struct {
	domain dnsname.FQDN
	dst    netip.Addr
}

// addrAssignments is the collection of addrs assigned by this client
// supporting lookup by magicip or domain+dst
type addrAssignments struct {
	byMagicIP   map[netip.Addr]addrs
	byDomainDst map[domainDst]addrs
}

func (a *addrAssignments) insert(as addrs) error {
	// we likely will want to allow overwriting in the future when we
	// have address expiry, but for now this should not happen
	if _, ok := a.byMagicIP[as.magic]; ok {
		return errors.New("byMagicIP key exists")
	}
	ddst := domainDst{domain: as.domain, dst: as.dst}
	if _, ok := a.byDomainDst[ddst]; ok {
		return errors.New("byDomainDst key exists")
	}
	mak.Set(&a.byMagicIP, as.magic, as)
	mak.Set(&a.byDomainDst, ddst, as)
	return nil
}

func (a *addrAssignments) lookupByDomainDst(domain dnsname.FQDN, dst netip.Addr) (addrs, bool) {
	v, ok := a.byDomainDst[domainDst{domain: domain, dst: dst}]
	return v, ok
}
