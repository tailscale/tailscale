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
	"sync/atomic"
	"time"

	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
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

	dph := newDatapathHandler(e.conn25, e.conn25.logf)
	if err := e.installHooks(dph); err != nil {
		return err
	}
	profile, prefs := e.host.Profiles().CurrentProfileState()
	e.profileStateChange(profile, prefs, false)

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
	// including property changes (e.g. HostInfo, Capabilities, CapMap).
	e.host.Hooks().OnSelfChange.Add(e.onSelfChange)

	// Manage how we react profile state changes, which include
	// prefs changes.
	e.host.Hooks().ProfileStateChange.Add(e.profileStateChange)

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
	if addr, ok := c.client.transitIPForMagicIP(m); ok {
		return addr, nil
	}
	cfg, ok := c.getConfig()
	if !ok {
		return netip.Addr{}, nil
	}
	if !cfg.ipSets.v4Magic.Contains(m) && !cfg.ipSets.v6Magic.Contains(m) {
		return netip.Addr{}, nil
	}
	return netip.Addr{}, ErrUnmappedMagicIP
}

// ConnectorRealIPForTransitIPConnection implements [IPMapper].
func (c *Conn25) ConnectorRealIPForTransitIPConnection(src, transit netip.Addr) (netip.Addr, error) {
	if addr, ok := c.connector.realIPForTransitIPConnection(src, transit); ok {
		return addr, nil
	}
	cfg, ok := c.getConfig()
	if !ok {
		return netip.Addr{}, nil
	}
	if !cfg.ipSets.v4Transit.Contains(transit) && !cfg.ipSets.v6Transit.Contains(transit) {
		return netip.Addr{}, nil
	}
	return netip.Addr{}, ErrUnmappedSrcAndTransitIP
}

func (e *extension) getMagicRange() views.Slice[netip.Prefix] {
	cfg, ok := e.conn25.getConfig()
	if !ok {
		return views.Slice[netip.Prefix]{}
	}
	return views.SliceOf(slices.Concat(cfg.ipSets.v4Magic.Prefixes(), cfg.ipSets.v6Magic.Prefixes()))
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

// onSelfChange implements the [ipnext.Hooks.OnSelfChange] hook.
func (e *extension) onSelfChange(selfNode tailcfg.NodeView) {
	cfg, err := configFromNodeView(selfNode)
	if err != nil {
		e.conn25.logf("error generating config from self node view: %v", err)
		return
	}
	e.conn25.reconfig(cfg)
}

// profileStateChange implements the [ipnext.Hooks.ProfileStateChange] hook.
func (e *extension) profileStateChange(loginProfile ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	// TODO(mzb): Handle node changes. Wipe out all config?
	// We'll need to look at the ordering of this hook and onSelfChange.
	e.conn25.prefsAdvertiseConnector.Store(prefs.AppConnector().Advertise)
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
	config                  atomic.Pointer[config]
	prefsAdvertiseConnector atomic.Bool
	logf                    logger.Logf
	client                  *client
	connector               *connector
}

func (c *Conn25) getConfig() (*config, bool) {
	cfg := c.config.Load()
	return cfg, cfg.isConfigured
}

func (c *Conn25) isConfigured() bool {
	_, ok := c.getConfig()
	return ok
}

func newConn25(logf logger.Logf) *Conn25 {
	c := &Conn25{
		logf:      logf,
		connector: &connector{logf: logf},
	}
	c.config.Store(&config{}) // initialize with empty to avoid nil checks
	c.client = &client{
		logf:        logf,
		addrsCh:     make(chan addrs, 64),
		assignments: addrAssignments{clock: tstime.StdClock{}},
		getIPSets: func() ipSets {
			cfg, ok := c.getConfig()
			if !ok {
				return emptyIPSets()
			}
			return cfg.ipSets
		},
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

func (c *Conn25) reconfig(cfg *config) {
	c.config.Store(cfg)
	c.client.reconfig()
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
	resp := ConnectorTransitIPResponse{}
	cfg, ok := c.getConfig()
	if !ok {
		// TODO(mzb): If this node is no longer configured at the
		// the time of this call, perhaps there should be a top-level
		// error, instead of error-per-TransitIP?
		for range ctipr.TransitIPs {
			resp.TransitIPs = append(resp.TransitIPs, TransitIPResponse{
				Code:    UnknownAppName,
				Message: unknownAppNameMessage,
			})
		}
		return resp
	}

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

	seen := map[netip.Addr]bool{}
	for _, each := range ctipr.TransitIPs {
		if seen[each.TransitIP] {
			resp.TransitIPs = append(resp.TransitIPs, TransitIPResponse{
				Code:    DuplicateTransitIP,
				Message: dupeTransitIPMessage,
			})
			c.logf("[Unexpected] peer attempt to map a transit IP reused a transitIP: node: %s, IP: %v",
				n.StableID(), each.TransitIP)
			continue
		}

		if _, ok := cfg.appsByName[each.App]; !ok {
			resp.TransitIPs = append(resp.TransitIPs, TransitIPResponse{
				Code:    UnknownAppName,
				Message: unknownAppNameMessage,
			})
			c.logf("[Unexpected] peer attempt to map a transit IP referenced unknown app: node: %s, app: %q",
				n.StableID(), each.App)
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

// ipSets wraps all the IPSets the config needs.
type ipSets struct {
	v4Transit *netipx.IPSet
	v4Magic   *netipx.IPSet
	v6Transit *netipx.IPSet
	v6Magic   *netipx.IPSet
}

func emptyIPSets() ipSets {
	return ipSets{
		v4Transit: &netipx.IPSet{},
		v4Magic:   &netipx.IPSet{},
		v6Transit: &netipx.IPSet{},
		v6Magic:   &netipx.IPSet{},
	}
}

// config holds the config derived from the self node view,
// which includes the policy.
// config is not safe for concurrent use.
type config struct {
	isConfigured       bool
	apps               []appctype.Conn25Attr
	appsByName         map[string]appctype.Conn25Attr
	appNamesByDomain   map[dnsname.FQDN][]string
	appNamesByWCDomain map[dnsname.FQDN][]string
	selfAppNames       set.Set[string]
	ipSets             ipSets
}

func configFromNodeView(n tailcfg.NodeView) (*config, error) {
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.Conn25Attr](n.CapMap(), AppConnectorsExperimentalAttrName)
	if err != nil {
		return &config{}, err
	}
	if len(apps) == 0 {
		return &config{}, nil
	}
	selfTags := set.SetOf(n.Tags().AsSlice())
	cfg := &config{
		isConfigured:       true,
		apps:               apps,
		appsByName:         map[string]appctype.Conn25Attr{},
		appNamesByDomain:   map[dnsname.FQDN][]string{},
		appNamesByWCDomain: map[dnsname.FQDN][]string{},
		selfAppNames:       set.Set[string]{},
		ipSets:             emptyIPSets(),
	}
	for _, app := range apps {
		normalizedDomains := set.Set[dnsname.FQDN]{}
		normalizedWCDomains := set.Set[dnsname.FQDN]{}
		for _, d := range app.Domains {
			domain, isWild := strings.CutPrefix(d, "*.")
			fqdn, err := normalizeDNSName(domain)
			if err != nil {
				return &config{}, err
			}
			if isWild && !normalizedWCDomains.Contains(fqdn) {
				normalizedWCDomains.Add(fqdn)
				mak.Set(&cfg.appNamesByWCDomain, fqdn, append(cfg.appNamesByWCDomain[fqdn], app.Name))
			} else if !isWild && !normalizedDomains.Contains(fqdn) {
				normalizedDomains.Add(fqdn)
				mak.Set(&cfg.appNamesByDomain, fqdn, append(cfg.appNamesByDomain[fqdn], app.Name))
			}
		}
		mak.Set(&cfg.appsByName, app.Name, app)
		if slices.ContainsFunc(app.Connectors, selfTags.Contains) {
			cfg.selfAppNames.Add(app.Name)
		}

	}

	// TODO(fran) 2026-03-18 we don't yet have a proper way to communicate the
	// global IP pool config. For now just take it from the first app.
	if len(apps) != 0 {
		app := apps[0]
		v4Mipp, err := ipSetFromIPRanges(app.V4MagicIPPool)
		if err != nil {
			return &config{}, err
		}
		v4Tipp, err := ipSetFromIPRanges(app.V4TransitIPPool)
		if err != nil {
			return &config{}, err
		}
		v6Mipp, err := ipSetFromIPRanges(app.V6MagicIPPool)
		if err != nil {
			return &config{}, err
		}
		v6Tipp, err := ipSetFromIPRanges(app.V6TransitIPPool)
		if err != nil {
			return &config{}, err
		}
		ipSets := ipSets{
			v4Magic:   v4Mipp,
			v4Transit: v4Tipp,
			v6Magic:   v6Mipp,
			v6Transit: v6Tipp,
		}
		cfg.ipSets = ipSets
	}
	return cfg, nil
}

// client performs the conn25 functionality for clients of connectors
// It allocates magic and transit IP addresses and communicates them with
// connectors.
// It's safe for concurrent use.
type client struct {
	logf      logger.Logf
	addrsCh   chan addrs
	getIPSets func() ipSets

	mu              sync.Mutex // protects the fields below
	v4MagicIPPool   *ippool
	v4TransitIPPool *ippool
	v6MagicIPPool   *ippool
	v6TransitIPPool *ippool
	assignments     addrAssignments
	byConnKey       map[key.NodePublic]set.Set[netip.Prefix]
}

// transitIPForMagicIP is part of the implementation of the IPMapper interface for dataflows lookups.
// See also [IPMapper.ClientTransitIPForMagicIP].
func (c *client) transitIPForMagicIP(magicIP netip.Addr) (netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.assignments.lookupByMagicIP(magicIP)
	if ok {
		return v.transit, true
	}
	return netip.Addr{}, false
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

func (c *client) reconfig() {
	c.mu.Lock()
	defer c.mu.Unlock()

	ipSets := c.getIPSets()

	c.v4MagicIPPool = newIPPool(ipSets.v4Magic)
	c.v4TransitIPPool = newIPPool(ipSets.v4Transit)
	c.v6MagicIPPool = newIPPool(ipSets.v6Magic)
	c.v6TransitIPPool = newIPPool(ipSets.v6Transit)
}

// getAppsForConnectorDomain returns the slice of app names which match the
// provided domain. Apps which match the domain exactly are preferred,
// otherwise the list of apps comes from the wildcard domain which matches
// the longest suffix of the specified domain. A nil or empty slice is returned
// if no match is found or if the list of matching apps would contain an app
// which is being handled by the self-node's connector.
func (cfg *config) getAppsForConnectorDomain(domain dnsname.FQDN, prefsAdvertiseConnector bool) []string {
	// Lookup exact matches first
	appNames := cfg.appNamesByDomain[domain]
	if len(appNames) == 0 {
		// No exact match, check wildcard domains
		// We have made the decision that wildcards will match the base domain.
		// So example.com will be a match for *.example.com, because we think that
		// this is most likely what users will expect.
		for d := domain; d != ""; d = d.Parent() {
			if appNames = cfg.appNamesByWCDomain[d]; len(appNames) > 0 {
				break
			}
		}
	}

	// If we have a candidate match, make sure that no candidate app is pointing
	// at a connector on the self-node.
	if len(appNames) == 0 || (prefsAdvertiseConnector && slices.ContainsFunc(appNames, cfg.selfAppNames.Contains)) {
		return nil
	}
	return appNames
}

// reserveAddresses tries to make an assignment of addrs from the address pools
// for this domain+dst address, so that this client can use conn25 connectors.
// The name of the matching app is also provided, no validation is done to check whether or not
// the app name refers to a configured app.
// It checks that this domain should be routed and that this client is not itself a connector for the domain
// and generally if it is valid to make the assignment.
func (c *client) reserveAddresses(appName string, domain dnsname.FQDN, dst netip.Addr) (addrs, error) {
	if !dst.IsValid() {
		return addrs{}, errors.New("dst is not valid")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.assignments.lookupByDomainDst(domain, dst); ok {
		return existing, nil
	}

	var mip, tip netip.Addr
	var err error
	if dst.Is4() {
		mip, err = c.v4MagicIPPool.next()
		if err != nil {
			return addrs{}, err
		}
		tip, err = c.v4TransitIPPool.next()
		if err != nil {
			return addrs{}, err
		}
	} else if dst.Is6() {
		mip, err = c.v6MagicIPPool.next()
		if err != nil {
			return addrs{}, err
		}
		tip, err = c.v6TransitIPPool.next()
		if err != nil {
			return addrs{}, err
		}
	} else {
		return addrs{}, errors.New("unexpected neither 4 nor 6")
	}
	as := addrs{
		dst:     dst,
		magic:   mip,
		transit: tip,
		app:     appName,
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
	return c.insertTransitConnMapping(tip, conn.Key())
}

func (e *extension) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case as := <-e.conn25.client.addrsCh:
			if err := e.handleAddressAssignment(ctx, as); err != nil {
				e.conn25.logf("error handling transit IP assignment (app: %s, mip: %v, src: %v): %v", as.app, as.magic, as.dst, err)
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
	tips, ok := c.lookupTransitIPsByConnKey(k)
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
	cfg, ok := e.conn25.getConfig()
	if !ok {
		return tailcfg.NodeView{}, errors.New("not configured")
	}
	app, ok := cfg.appsByName[as.app]
	if !ok {
		e.conn25.logf("App not found for app: %s (domain: %s)", as.app, as.domain)
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

// mapDNSResponse parses and inspects the DNS response. If the domain
// is determined to belong to app this node is client for, it assigns addresses
// for connecting and rewrites the response to contain Magic IPs.
func (c *Conn25) mapDNSResponse(buf []byte) []byte {
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

	cfg, ok := c.getConfig()
	if !ok {
		return buf
	}

	appNames := cfg.getAppsForConnectorDomain(queriedDomain, c.prefsAdvertiseConnector.Load())
	if len(appNames) == 0 {
		return buf
	}

	// There is guaranteed to be at least one matching app, so just take the first one for now
	appName := appNames[0]

	// Now we know this is a dns response we think we should rewrite, we're going to provide our response which
	// currently means we will:
	//  * write the questions through as they are
	//  * not send through the additional section
	//  * provide our answers, or no answers if we don't handle those answers (possibly in the future we should write through answers for eg TypeTXT)
	var answers []dnsResponseRewrite
	if question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA {
		c.logf("mapping dns response for connector domain, unsupported type: %v", question.Type)
		newBuf, err := c.client.rewriteDNSResponse(appName, hdr, questions, answers)
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
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			if h.Type != question.Type {
				// would not expect a v4 response to a v6 question or vice versa, don't add a rewrite for this.
				if err := p.SkipAnswer(); err != nil {
					c.logf("error parsing dns response: %v", err)
					return makeServFail(c.logf, hdr, question)
				}
				continue
			}
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
			var dstAddr netip.Addr
			if h.Type == dnsmessage.TypeA {
				r, err := p.AResource()
				if err != nil {
					c.logf("error parsing dns response: %v", err)
					return makeServFail(c.logf, hdr, question)
				}
				dstAddr = netip.AddrFrom4(r.A)
			} else {
				r, err := p.AAAAResource()
				if err != nil {
					c.logf("error parsing dns response: %v", err)
					return makeServFail(c.logf, hdr, question)
				}
				dstAddr = netip.AddrFrom16(r.AAAA)
			}
			answers = append(answers, dnsResponseRewrite{domain: domain, dst: dstAddr})
		default:
			// we already checked the question was for a supported type, this answer is unexpected
			c.logf("unexpected type for connector domain dns response: %v %v", queriedDomain, h.Type)
			if err := p.SkipAnswer(); err != nil {
				c.logf("error parsing dns response: %v", err)
				return makeServFail(c.logf, hdr, question)
			}
		}
	}
	newBuf, err := c.client.rewriteDNSResponse(appName, hdr, questions, answers)
	if err != nil {
		c.logf("error rewriting dns response: %v", err)
		return makeServFail(c.logf, hdr, question)
	}
	return newBuf
}

func (c *client) rewriteDNSResponse(appName string, hdr dnsmessage.Header, questions []dnsmessage.Question, answers []dnsResponseRewrite) ([]byte, error) {
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
		as, err := c.reserveAddresses(appName, rw.domain, rw.dst)
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
		if rw.dst.Is4() {
			rhdr := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0}
			if err := b.AResource(rhdr, dnsmessage.AResource{A: as.magic.As4()}); err != nil {
				return nil, err
			}
		} else if rw.dst.Is6() {
			rhdr := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 0}
			if err := b.AAAAResource(rhdr, dnsmessage.AAAAResource{AAAA: as.magic.As16()}); err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("unexpected neither 4 nor 6")
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
}

// realIPForTransitIPConnection is part of the implementation of the IPMapper interface for dataflows lookups.
// See also [IPMapper.ConnectorRealIPForTransitIPConnection].
func (c *connector) realIPForTransitIPConnection(srcIP netip.Addr, transitIP netip.Addr) (netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.lookupBySrcIPAndTransitIP(srcIP, transitIP)
	if ok {
		return v.addr, true
	}
	return netip.Addr{}, false
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

type addrs struct {
	dst       netip.Addr
	magic     netip.Addr
	transit   netip.Addr
	domain    dnsname.FQDN
	app       string
	expiresAt time.Time
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
	clock       tstime.Clock
}

const defaultExpiry = 48 * time.Hour

func (a *addrAssignments) insert(as addrs) error {
	return a.insertWithExpiry(as, defaultExpiry)
}

func (a *addrAssignments) insertWithExpiry(as addrs, d time.Duration) error {
	if !as.expiresAt.IsZero() {
		return errors.New("expiresAt already set")
	}
	now := a.clock.Now()
	as.expiresAt = now.Add(d)
	// we don't expect for addresses to be reused before expiry
	if existing, ok := a.byMagicIP[as.magic]; ok {
		if !existing.expiresAt.Before(now) {
			return errors.New("byMagicIP key exists")
		}
	}
	ddst := domainDst{domain: as.domain, dst: as.dst}
	if existing, ok := a.byDomainDst[ddst]; ok {
		if !existing.expiresAt.Before(now) {
			return errors.New("byDomainDst key exists")
		}
	}
	if existing, ok := a.byTransitIP[as.transit]; ok {
		if !existing.expiresAt.Before(now) {
			return errors.New("byTransitIP key exists")
		}
	}
	mak.Set(&a.byMagicIP, as.magic, as)
	mak.Set(&a.byTransitIP, as.transit, as)
	mak.Set(&a.byDomainDst, ddst, as)
	return nil
}

func (a *addrAssignments) lookupByDomainDst(domain dnsname.FQDN, dst netip.Addr) (addrs, bool) {
	v, ok := a.byDomainDst[domainDst{domain: domain, dst: dst}]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByMagicIP(mip netip.Addr) (addrs, bool) {
	v, ok := a.byMagicIP[mip]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return addrs{}, false
	}
	return v, true
}

func (a *addrAssignments) lookupByTransitIP(tip netip.Addr) (addrs, bool) {
	v, ok := a.byTransitIP[tip]
	if !ok || v.expiresAt.Before(a.clock.Now()) {
		return addrs{}, false
	}
	return v, true
}

// insertTransitConnMapping adds an entry to the byConnKey map
// for the provided transitIP (as a prefix).
// The provided transitIP must already be present in the byTransitIP map.
func (c *client) insertTransitConnMapping(tip netip.Addr, connKey key.NodePublic) error {
	if _, ok := c.assignments.lookupByTransitIP(tip); !ok {
		return errors.New("transit IP is not already known")
	}

	ctips, ok := c.byConnKey[connKey]
	tipp := netip.PrefixFrom(tip, tip.BitLen())
	if ok {
		if ctips.Contains(tipp) {
			return errors.New("byConnKey already contains transit")
		}
	} else {
		ctips.Make()
		mak.Set(&c.byConnKey, connKey, ctips)
	}
	ctips.Add(tipp)
	return nil
}

// lookupTransitIPsByConnKey returns a slice containing the transit IPs (as netipPrefix)
// associated with the given connector (identified by node key), or (nil, false) if there is no entry
// for the given key.
func (c *client) lookupTransitIPsByConnKey(k key.NodePublic) ([]netip.Prefix, bool) {
	s, ok := c.byConnKey[k]
	if !ok {
		return nil, false
	}
	return s.Slice(), true
}
