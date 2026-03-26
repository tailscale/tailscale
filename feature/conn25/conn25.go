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
	"strings"
	"sync"

	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
	"tailscale.com/util/testenv"
	"tailscale.com/wgengine/filter"
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

func normalizeDNSName(name string) (dnsname.FQDN, error) {
	// note that appconnector does this same thing, tsdns has its own custom lower casing
	// it might be good to unify in a function in dnsname package.
	return dnsname.ToFQDN(strings.ToLower(name))
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
	// TODO(tailscale/corp#39033): Remove for alpha release.
	if !envknob.UseWIPCode() && !testenv.InTest() {
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
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
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string {
	return featureName
}

// Init implements [ipnext.Extension].
func (e *extension) Init(host ipnext.Host) error {
	// TODO(tailscale/corp#39033): Remove for alpha release.
	if !envknob.UseWIPCode() && !testenv.InTest() {
		return ipnext.SkipExtension
	}

	if e.ctxCancel != nil {
		return nil
	}
	e.host = host

	dph := newDatapathHandler(e.conn25, e.conn25.client.logf)
	if err := e.installHooks(dph); err != nil {
		return err
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	e.ctxCancel = cancel
	go e.sendLoop(ctx)
	return nil
}

func (e *extension) installHooks(dph *datapathHandler) error {
	// Make sure we can access the DNS manager and the system tun.
	dnsManager, ok := e.backend.Sys().DNSManager.GetOK()
	if !ok {
		return errors.New("could not access system dns manager")
	}
	tun, ok := e.backend.Sys().Tun.GetOK()
	if !ok {
		return errors.New("could not access system tun")
	}

	// Set up the DNS manager to rewrite responses for app domains
	// to answer with Magic IPs.
	dnsManager.SetQueryResponseMapper(func(bs []byte) []byte {
		if !e.conn25.isConfigured() {
			return bs
		}
		return e.conn25.mapDNSResponse(bs)
	})

	// Intercept packets from the tun device and from WireGuard
	// to perform DNAT and SNAT.
	tun.PreFilterPacketOutboundToWireGuardAppConnectorIntercept = func(p *packet.Parsed, _ *tstun.Wrapper) filter.Response {
		if !e.conn25.isConfigured() {
			return filter.Accept
		}
		return dph.HandlePacketFromTunDevice(p)
	}
	tun.PostFilterPacketInboundFromWireGuardAppConnector = func(p *packet.Parsed, _ *tstun.Wrapper) filter.Response {
		if !e.conn25.isConfigured() {
			return filter.Accept
		}
		return dph.HandlePacketFromWireGuard(p)
	}

	// Manage how we react to changes to the current node,
	// including property changes (e.g. HostInfo, Capabilities, CapMap)
	// and profile switches.
	e.host.Hooks().OnSelfChange.Add(e.onSelfChange)

	// Allow the client to send packets with Transit IP destinations
	// in the link-local space.
	e.host.Hooks().Filter.LinkLocalAllowHooks.Add(func(p packet.Parsed) (bool, string) {
		if !e.conn25.isConfigured() {
			return false, ""
		}
		return e.conn25.client.linkLocalAllow(p)
	})

	// Allow the connector to receive packets with Transit IP destinations
	// in the link-local space.
	e.host.Hooks().Filter.LinkLocalAllowHooks.Add(func(p packet.Parsed) (bool, string) {
		if !e.conn25.isConfigured() {
			return false, ""
		}
		return e.conn25.connector.packetFilterAllow(p)
	})

	// Allow the connector to receive packets with Transit IP destinations
	// that are not "local" to it, and that it does not advertise.
	e.host.Hooks().Filter.IngressAllowHooks.Add(func(p packet.Parsed) (bool, string) {
		if !e.conn25.isConfigured() {
			return false, ""
		}
		return e.conn25.connector.packetFilterAllow(p)
	})

	// Give the client the Magic IP range to install on the OS.
	e.host.Hooks().ExtraRouterConfigRoutes.Set(func() views.Slice[netip.Prefix] {
		if !e.conn25.isConfigured() {
			return views.Slice[netip.Prefix]{}
		}
		return e.getMagicRange()
	})

	// Tell WireGuard what Transit IPs belong to which connector peers.
	e.host.Hooks().ExtraWireGuardAllowedIPs.Set(func(k key.NodePublic) views.Slice[netip.Prefix] {
		if !e.conn25.isConfigured() {
			return views.Slice[netip.Prefix]{}
		}
		return e.extraWireGuardAllowedIPs(k)
	})

	return nil
}

// ClientTransitIPForMagicIP implements [IPMapper].
func (c *Conn25) ClientTransitIPForMagicIP(m netip.Addr) (netip.Addr, error) {
	return c.client.transitIPForMagicIP(m)
}

// ConnectorRealIPForTransitIPConnection implements [IPMapper].
func (c *Conn25) ConnectorRealIPForTransitIPConnection(src, transit netip.Addr) (netip.Addr, error) {
	return c.connector.realIPForTransitIPConnection(src, transit)
}

func (e *extension) getMagicRange() views.Slice[netip.Prefix] {
	cfg := e.conn25.client.getConfig()
	return views.SliceOf(cfg.magicIPSet.Prefixes())
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
}

func (e *extension) extraWireGuardAllowedIPs(k key.NodePublic) views.Slice[netip.Prefix] {
	return e.conn25.client.extraWireGuardAllowedIPs(k)
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
// contents to assign addresses for connecting.
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

func (c *connector) handleTransitIPRequest(n tailcfg.NodeView, peerV4 netip.Addr, peerV6 netip.Addr, tipr TransitIPRequest) TransitIPResponse {
	if tipr.TransitIP.Is4() != tipr.DestinationIP.Is4() {
		c.logf("[Unexpected] peer attempt to map a transit IP to dest IP did not have matching families: node: %s, tIPv4: %v dIPv4: %v",
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
		c.logf("[Unexpected] peer attempt to map a transit IP did not have a matching address family: node: %s, IPv4: %v",
			n.StableID(), tipr.TransitIP.Is4())
		return TransitIPResponse{NoMatchingPeerIPFamily, noMatchingPeerIPFamilyMessage}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.config.appsByName[tipr.App]; !ok {
		c.logf("[Unexpected] peer attempt to map a transit IP referenced unknown app: node: %s, app: %q",
			n.StableID(), tipr.App)
		return TransitIPResponse{Code: UnknownAppName, Message: unknownAppNameMessage}
	}

	if c.transitIPs == nil {
		c.transitIPs = make(map[netip.Addr]map[netip.Addr]appAddr)
	}
	peerMap, ok := c.transitIPs[peerAddr]
	if !ok {
		peerMap = make(map[netip.Addr]appAddr)
		c.transitIPs[peerAddr] = peerMap
	}
	peerMap[tipr.TransitIP] = appAddr{addr: tipr.DestinationIP, app: tipr.App}
	return TransitIPResponse{}
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
	transitIPSet      netipx.IPSet
	magicIPSet        netipx.IPSet
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
			fqdn, err := normalizeDNSName(d)
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
	// TODO(fran) 2026-03-18 we don't yet have a proper way to communicate the
	// global IP pool config. For now just take it from the first app.
	if len(apps) != 0 {
		app := apps[0]
		mipp, err := ipSetFromIPRanges(app.MagicIPPool)
		if err != nil {
			return config{}, err
		}
		tipp, err := ipSetFromIPRanges(app.TransitIPPool)
		if err != nil {
			return config{}, err
		}
		cfg.magicIPSet = *mipp
		cfg.transitIPSet = *tipp
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

func (c *client) getConfig() config {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.config
}

// transitIPForMagicIP is part of the implementation of the IPMapper interface for dataflows lookups.
// See also [IPMapper.ClientTransitIPForMagicIP].
func (c *client) transitIPForMagicIP(magicIP netip.Addr) (netip.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.assignments.lookupByMagicIP(magicIP)
	if ok {
		return v.transit, nil
	}
	if !c.config.magicIPSet.Contains(magicIP) {
		return netip.Addr{}, nil
	}
	return netip.Addr{}, ErrUnmappedMagicIP
}

// linkLocalAllow returns true if the provided packet with a link-local Dst address has a
// Dst that is one of our transit IPs, and false otherwise.
// Tailscale's wireguard filters drop link-local unicast packets (see [wgengine/filter/filter.go])
// but conn25 uses link-local addresses for transit IPs.
// Let the filter know if this is one of our addresses and should be allowed.
func (c *client) linkLocalAllow(p packet.Parsed) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ok := c.isKnownTransitIP(p.Dst.Addr())
	if ok {
		return true, packetFilterAllowReason
	}
	return false, ""
}

func (c *client) isKnownTransitIP(tip netip.Addr) bool {
	_, ok := c.assignments.lookupByTransitIP(tip)
	return ok
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

	c.magicIPPool = newIPPool(&(newCfg.magicIPSet))
	c.transitIPPool = newIPPool(&(newCfg.transitIPSet))
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
	if len(appNames) == 0 {
		return addrs{}, fmt.Errorf("no app names found for domain %q", domain)
	}
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

func (c *client) addTransitIPForConnector(tip netip.Addr, conn tailcfg.NodeView) error {
	if conn.Key().IsZero() {
		return fmt.Errorf("node with stable ID %q does not have a key", conn.StableID())
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.assignments.insertTransitConnMapping(tip, conn.Key())
}

func (e *extension) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case as := <-e.conn25.client.addrsCh:
			if err := e.handleAddressAssignment(ctx, as); err != nil {
				e.conn25.client.logf("error handling transit IP assignment (app: %s, mip: %v, src: %v): %v", as.app, as.magic, as.dst, err)
			}
		}
	}
}

func (e *extension) handleAddressAssignment(ctx context.Context, as addrs) error {
	conn, err := e.sendAddressAssignment(ctx, as)
	if err != nil {
		return err
	}
	err = e.conn25.client.addTransitIPForConnector(as.transit, conn)
	if err != nil {
		return err
	}

	e.host.AuthReconfigAsync()
	return nil
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

func (c *client) extraWireGuardAllowedIPs(k key.NodePublic) views.Slice[netip.Prefix] {
	c.mu.Lock()
	defer c.mu.Unlock()
	tips, ok := c.assignments.lookupTransitIPsByConnKey(k)
	if !ok {
		return views.Slice[netip.Prefix]{}
	}
	return views.SliceOf(tips)
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

func (e *extension) sendAddressAssignment(ctx context.Context, as addrs) (tailcfg.NodeView, error) {
	app, ok := e.conn25.client.getConfig().appsByName[as.app]
	if !ok {
		e.conn25.client.logf("App not found for app: %s (domain: %s)", as.app, as.domain)
		return tailcfg.NodeView{}, errors.New("app not found")
	}

	nb := e.host.NodeBackend()
	peers := appc.PickConnector(nb, app)
	var urlBase string
	var conn tailcfg.NodeView
	for _, p := range peers {
		urlBase = nb.PeerAPIBase(p)
		if urlBase != "" {
			conn = p
			break
		}
	}
	if urlBase == "" {
		return tailcfg.NodeView{}, errors.New("no connector peer found to handle address assignment")
	}
	client := e.backend.Sys().Dialer.Get().PeerAPIHTTPClient()
	return conn, makePeerAPIReq(ctx, client, urlBase, as)
}

type dnsResponseRewrite struct {
	domain dnsname.FQDN
	dst    netip.Addr
}

func makeServFail(logf logger.Logf, h dnsmessage.Header, q dnsmessage.Question) []byte {
	h.Response = true
	h.Authoritative = true
	h.RCode = dnsmessage.RCodeServerFailure
	b := dnsmessage.NewBuilder(nil, h)
	err := b.StartQuestions()
	if err != nil {
		logf("error making servfail: %v", err)
		return []byte{}
	}
	err = b.Question(q)
	if err != nil {
		logf("error making servfail: %v", err)
		return []byte{}
	}
	bs, err := b.Finish()
	if err != nil {
		// If there's an error here there's a bug somewhere directly above.
		// _possibly_ some kind of question that was parseable but not encodable?,
		// otherwise we could panic.
		logf("error making servfail: %v", err)
	}
	return bs
}

func (c *client) mapDNSResponse(buf []byte) []byte {
	var p dnsmessage.Parser
	hdr, err := p.Start(buf)
	if err != nil {
		c.logf("error parsing dns response: %v", err)
		return buf
	}
	questions, err := p.AllQuestions()
	if err != nil {
		c.logf("error parsing dns response: %v", err)
		return buf
	}
	// Any message we are interested in has one question (RFC 9619)
	if len(questions) != 1 {
		return buf
	}
	question := questions[0]
	// The other Class types are not commonly used and supporting them hasn't been considered.
	if question.Class != dnsmessage.ClassINET {
		return buf
	}
	queriedDomain, err := normalizeDNSName(question.Name.String())
	if err != nil {
		return buf
	}
	if !c.isConnectorDomain(queriedDomain) {
		return buf
	}

	// Now we know this is a dns response we think we should rewrite, we're going to provide our response which
	// currently means we will:
	//  * write the questions through as they are
	//  * not send through the additional section
	//  * provide our answers, or no answers if we don't handle those answers (possibly in the future we should write through answers for eg TypeTXT)
	var answers []dnsResponseRewrite
	if question.Type != dnsmessage.TypeA {
		// we plan to support TypeAAAA soon (2026-03-11)
		c.logf("mapping dns response for connector domain, unsupported type: %v", question.Type)
		newBuf, err := c.rewriteDNSResponse(hdr, questions, answers)
		if err != nil {
			c.logf("error writing empty response for unsupported type: %v", err)
			return makeServFail(c.logf, hdr, question)
		}
		return newBuf
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			c.logf("error parsing dns response: %v", err)
			return makeServFail(c.logf, hdr, question)
		}
		// other classes are unsupported, and we checked the question was for ClassINET already
		if h.Class != dnsmessage.ClassINET {
			c.logf("unexpected class for connector domain dns response: %v %v", queriedDomain, h.Class)
			if err := p.SkipAnswer(); err != nil {
				c.logf("error parsing dns response: %v", err)
				return makeServFail(c.logf, hdr, question)
			}
			continue
		}
		switch h.Type {
		case dnsmessage.TypeCNAME:
			// An A record was asked for, and the answer is a CNAME, this answer will tell us which domain it's a CNAME for
			// and a subsequent answer should tell us what the target domains address is (or possibly another CNAME). Drop
			// this for now (2026-03-11) but in the near future we should collapse the CNAME chain and map to the ultimate
			// destination address (see eg appc/{appconnector,observe}.go).
			c.logf("not yet implemented CNAME answer: %v", queriedDomain)
			if err := p.SkipAnswer(); err != nil {
				c.logf("error parsing dns response: %v", err)
				return makeServFail(c.logf, hdr, question)
			}
		case dnsmessage.TypeA:
			domain, err := normalizeDNSName(h.Name.String())
			if err != nil {
				c.logf("bad dnsname: %v", err)
				return makeServFail(c.logf, hdr, question)
			}
			// answers should be for the domain that was queried
			if domain != queriedDomain {
				c.logf("unexpected domain for connector domain dns response: %v %v", queriedDomain, domain)
				if err := p.SkipAnswer(); err != nil {
					c.logf("error parsing dns response: %v", err)
					return makeServFail(c.logf, hdr, question)
				}
				continue
			}
			r, err := p.AResource()
			if err != nil {
				c.logf("error parsing dns response: %v", err)
				return makeServFail(c.logf, hdr, question)
			}
			answers = append(answers, dnsResponseRewrite{domain: domain, dst: netip.AddrFrom4(r.A)})
		default:
			// we already checked the question was for a supported type, this answer is unexpected
			c.logf("unexpected type for connector domain dns response: %v %v", queriedDomain, h.Type)
			if err := p.SkipAnswer(); err != nil {
				c.logf("error parsing dns response: %v", err)
				return makeServFail(c.logf, hdr, question)
			}
		}
	}
	newBuf, err := c.rewriteDNSResponse(hdr, questions, answers)
	if err != nil {
		c.logf("error rewriting dns response: %v", err)
		return makeServFail(c.logf, hdr, question)
	}
	return newBuf
}

func (c *client) rewriteDNSResponse(hdr dnsmessage.Header, questions []dnsmessage.Question, answers []dnsResponseRewrite) ([]byte, error) {
	// We are currently (2026-03-10) only doing this for AResource records, we know that if we are here
	// with non-empty answers, the type was AResource.
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range questions {
		if err := b.Question(q); err != nil {
			return nil, err
		}
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}

	// make an answer for each rewrite
	for _, rw := range answers {
		as, err := c.reserveAddresses(rw.domain, rw.dst)
		if err != nil {
			return nil, err
		}
		if !as.isValid() {
			return nil, errors.New("connector addresses empty")
		}
		name, err := dnsmessage.NewName(rw.domain.WithTrailingDot())
		if err != nil {
			return nil, err
		}
		// only handling TypeA right now
		rhdr := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0}
		if err := b.AResource(rhdr, dnsmessage.AResource{A: as.magic.As4()}); err != nil {
			return nil, err
		}
	}
	// We do _not_ include the additional section in our rewrite. (We don't want to include
	// eg DNSSEC info, or other extra info like related records).
	out, err := b.Finish()
	if err != nil {
		return nil, err
	}
	return out, nil
}

type connector struct {
	logf logger.Logf

	mu sync.Mutex // protects the fields below
	// transitIPs is a map of connector client peer IP -> client transitIPs that we update as connector client peers instruct us to, and then use to route traffic to its destination on behalf of connector clients.
	// Note that each peer could potentially have two maps: one for its IPv4 address, and one for its IPv6 address. The transit IPs map for a given peer IP will contain transit IPs of the same family as the peer's IP.
	transitIPs map[netip.Addr]map[netip.Addr]appAddr
	config     config
}

// realIPForTransitIPConnection is part of the implementation of the IPMapper interface for dataflows lookups.
// See also [IPMapper.ConnectorRealIPForTransitIPConnection].
func (c *connector) realIPForTransitIPConnection(srcIP netip.Addr, transitIP netip.Addr) (netip.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.lookupBySrcIPAndTransitIP(srcIP, transitIP)
	if ok {
		return v.addr, nil
	}
	if !c.config.transitIPSet.Contains(transitIP) {
		return netip.Addr{}, nil
	}
	return netip.Addr{}, ErrUnmappedSrcAndTransitIP
}

const packetFilterAllowReason = "app connector transit IP"

// packetFilterAllow returns true if the provided packet has a Src that maps to a peer
// that has a transit IP with us that is the packet Dst, and false otherwise.
func (c *connector) packetFilterAllow(p packet.Parsed) (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.lookupBySrcIPAndTransitIP(p.Src.Addr(), p.Dst.Addr())
	if ok {
		return true, packetFilterAllowReason
	}
	return false, ""
}

func (c *connector) lookupBySrcIPAndTransitIP(srcIP, transitIP netip.Addr) (appAddr, bool) {
	m, ok := c.transitIPs[srcIP]
	if !ok || m == nil {
		return appAddr{}, false
	}
	v, ok := m[transitIP]
	return v, ok
}

func (c *connector) reconfig(newCfg config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = newCfg
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
// supporting lookup by magic IP, transit IP or domain+dst, or to lookup all
// transit IPs associated with a given connector (identified by its node key).
// byConnKey stores netip.Prefix versions of the transit IPs for use in the
// WireGuard hooks.
type addrAssignments struct {
	byMagicIP   map[netip.Addr]addrs
	byTransitIP map[netip.Addr]addrs
	byDomainDst map[domainDst]addrs
	byConnKey   map[key.NodePublic]set.Set[netip.Prefix]
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
	if _, ok := a.byTransitIP[as.transit]; ok {
		return errors.New("byTransitIP key exists")
	}

	mak.Set(&a.byMagicIP, as.magic, as)
	mak.Set(&a.byTransitIP, as.transit, as)
	mak.Set(&a.byDomainDst, ddst, as)
	return nil
}

// insertTransitConnMapping adds an entry to the byConnKey map
// for the provided transitIP (as a prefix).
// The provided transitIP must already be present in the byTransitIP map.
func (a *addrAssignments) insertTransitConnMapping(tip netip.Addr, connKey key.NodePublic) error {
	if _, ok := a.lookupByTransitIP(tip); !ok {
		return errors.New("transit IP is not already known")
	}

	ctips, ok := a.byConnKey[connKey]
	tipp := netip.PrefixFrom(tip, tip.BitLen())
	if ok {
		if ctips.Contains(tipp) {
			return errors.New("byConnKey already contains transit")
		}
	} else {
		ctips.Make()
		mak.Set(&a.byConnKey, connKey, ctips)
	}
	ctips.Add(tipp)
	return nil
}

func (a *addrAssignments) lookupByDomainDst(domain dnsname.FQDN, dst netip.Addr) (addrs, bool) {
	v, ok := a.byDomainDst[domainDst{domain: domain, dst: dst}]
	return v, ok
}

func (a *addrAssignments) lookupByMagicIP(mip netip.Addr) (addrs, bool) {
	v, ok := a.byMagicIP[mip]
	return v, ok
}

func (a *addrAssignments) lookupByTransitIP(tip netip.Addr) (addrs, bool) {
	v, ok := a.byTransitIP[tip]
	return v, ok
}

// lookupTransitIPsByConnKey returns a slice containing the transit IPs (as netipPrefix)
// associated with the given connector (identified by node key), or (nil, false) if there is no entry
// for the given key.
func (a *addrAssignments) lookupTransitIPsByConnKey(k key.NodePublic) ([]netip.Prefix, bool) {
	s, ok := a.byConnKey[k]
	if !ok {
		return nil, false
	}
	return s.Slice(), true
}
