// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package conn25 registers the conn25 feature and implements its associated ipnext.Extension.
// conn25 will be an app connector like feature that routes traffic for configured domains via
// connector devices and avoids the "too many routes" pitfall of app connector. It is currently
// (2026-02-04) some peer API routes for clients to tell connectors about their desired routing.
package conn25

import (
	"bytes"
	"container/list"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"

	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/packet"
	"tailscale.com/net/traffic"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tstun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/tstime"
	"tailscale.com/types/appctype"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/set"
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
	if !feature.Register(featureName) {
		return
	}
	ipnext.RegisterExtension(featureName, func(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
		return &extension{
			conn25:  newConn25(logger.WithPrefix(logf, "conn25: ")),
			backend: sb,
		}, nil
	})
	ipnlocal.RegisterPeerAPIHandler("/v0/connector/transit-ip", handleConnectorTransitIP)
	ipnlocal.HookReplyToDNSQueries.Add(handleHookReplyToDNSQueries)
	localapi.Register("conn25/state", serveLocalAPIStateGet)
	ipnlocal.RegisterC2N("GET /conn25/state", serveC2NStateGet)
	ipnlocal.HookPeerAPIDNSResponse.Add(handleHookPeerAPIDNSResponse)
}

func handleConnectorTransitIP(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	e, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		http.Error(w, "miswired", http.StatusInternalServerError)
		return
	}
	if !e.conn25.isConfigured() {
		http.Error(w, "conn25 not configured", http.StatusServiceUnavailable)
		return
	}
	e.handleConnectorTransitIP(h, w, r)
}

func handleHookReplyToDNSQueries(h ipnlocal.PeerAPIHandler, r *http.Request) (allowSource bool, allowName ipnlocal.DNSNameFilter) {
	e, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		return false, nil
	}
	return e.conn25.handleHookReplyToDNSQueries(h, r)
}

// extension is an [ipnext.Extension] managing the connector on platforms
// that import this package.
type extension struct {
	conn25                *Conn25            // safe for concurrent access and only set at creation
	backend               ipnext.SafeBackend // safe for concurrent access and only set at creation
	clearAllDatapathFlows func()             // safe for concurrent access and only set at creation

	host      ipnext.Host             // set in Init, read-only after
	ctxCancel context.CancelCauseFunc // cancels sendLoop goroutine
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string {
	return featureName
}

// Init implements [ipnext.Extension].
func (e *extension) Init(host ipnext.Host) error {
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
	dph.StartFlowExpirySweepers(ctx)
	e.conn25.connector.startExpirySweeper(ctx)
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
	r := dnsManager.Resolver()
	if r == nil {
		return errors.New("dns manager resolver not ready")
	}

	if err := r.RegisterCustomScheme(DNSAddrScheme, func(addr string) (string, error) {
		scheme, appName, ok := strings.Cut(addr, ":")
		if !ok || scheme != DNSAddrScheme {
			return "", fmt.Errorf("unexpected conn25 scheme %q", scheme)
		}

		if !e.conn25.isConfigured() {
			return "", errors.New("conn25 not configured")
		}
		cfg, ok := e.conn25.getConfig()
		if !ok {
			return "", errors.New("conn25 no config found")
		}
		app, ok := cfg.appsByName[appName]
		if !ok {
			return "", errors.New("no app found for app name")
		}
		urlBase := e.pickConnectorURLBase(app)
		if urlBase == "" {
			return "", nil
		}
		return fmt.Sprintf("%s/dns-query?app=%s", urlBase, url.QueryEscape(app.Name)), nil
	}); err != nil {
		return fmt.Errorf("could not register DNS resolver scheme: %w", err)
	}

	// Set up the DNS manager to rewrite responses for app domains
	// to answer with Magic IPs.
	dnsManager.SetQueryResponseMapper(func(res *resolver.Response) []byte {
		if !e.conn25.isConfigured() {
			return res.Bs
		}
		return e.mapDNSResponse(res)
	})

	// Intercept packets from the tun device and from WireGuard
	// to perform DNAT and SNAT.
	tun.PreFilterPacketOutboundToWireGuardAppConnectorIntercept.Store(func(p *packet.Parsed, tun *tstun.Wrapper) filter.Response {
		if !e.conn25.isConfigured() {
			return filter.Accept
		}
		return dph.HandlePacketFromTunDevice(p, tun)
	})
	tun.PostFilterPacketInboundFromWireGuardAppConnector.Store(func(p *packet.Parsed, tun *tstun.Wrapper) filter.Response {
		if !e.conn25.isConfigured() {
			return filter.Accept
		}
		return dph.HandlePacketFromWireGuard(p, tun)
	})
	tun.OnUnmappedTransitIPMessage.Store(func(pkt packet.TailscaleRejectedHeader) {
		if !e.conn25.isConfigured() {
			return
		}
		e.conn25.client.resendTransitIPMapping(pkt.Dst.Addr())
	})

	// The profile state change hook needs to clear all active flows on a
	// major change (eg. switching tailnets), so make that hook accessible
	// to it.
	e.clearAllDatapathFlows = dph.ClearAllActiveFlows

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
		return e.conn25.connector.linkLocalAllow(p)
	})

	// Allow the connector to receive packets with Transit IP destinations
	// that are not "local" to it, and that it does not advertise, as long as
	// the peer's grant for the app permits their protocol and port.
	e.host.Hooks().Filter.IngressAllowHooks.Add(func(p packet.Parsed) (bool, string) {
		if !e.conn25.isConfigured() {
			return false, ""
		}
		return e.conn25.connector.ingressAllow(p)
	})

	// Route DNS queries for app domains to the connector that serves
	// them, chosen at query time via the [DNSAddrScheme] scheme.
	e.host.Hooks().ExtraDNSRoutes.Set(func() map[string][]*dnstype.Resolver {
		if !e.conn25.isConfigured() {
			return nil
		}
		if e.conn25.prefsAdvertiseConnector.Load() {
			// A node that is itself a connector resolves app domains
			// directly rather than via another connector.
			return nil
		}
		return e.conn25.appDNSRoutes.Load()
	})

	// Give the client the Magic IP range to install on the OS.
	e.host.Hooks().ExtraRouterConfigRoutes.Set(func() views.Slice[netip.Prefix] {
		if !e.conn25.isConfigured() {
			return views.Slice[netip.Prefix]{}
		}
		return e.getMagicRange()
	})

	// Tell WireGuard what Transit IPs belong to which connector peers.
	e.host.Hooks().ExtraWireGuardAllowedIPs.Set(func(peers iter.Seq[tailcfg.NodeID]) map[tailcfg.NodeID][]netip.Prefix {
		if !e.conn25.isConfigured() {
			return nil
		}
		var extras map[tailcfg.NodeID][]netip.Prefix
		for id := range peers {
			if pfxs := e.extraWireGuardAllowedIPs(id); pfxs.Len() > 0 {
				mak.Set(&extras, id, pfxs.AsSlice())
			}
		}
		return extras
	})

	return nil
}

// ClientPrepareNewFlowForMagicIP implements [Conn25Datapath].
// The datapath notifies Conn25 that a flow to magic IP is being established, and
// Conn25 resolves m to its Transit IP and counts the flow against that address
// assignment in one step, reporting ok and returning the reference that names
// that Transit IP and keeps it and its associated addresses from being removed
// from Conn25's state and returned to their pools while the flow uses them.
//
// If m has an active address assignment whose Transit IP isn't routable yet, it
// reports ok false and returns [ErrTransitIPNotRoutable].
//
// If m has no active address assignment, it reports ok false and returns
// [ErrUnmappedMagicIP] when m falls in a configured Magic IP range, and a nil
// error when it does not, since in that case m is not a Magic IP at all and the
// traffic to it is potentially valid non-app-connector traffic.
func (c *Conn25) ClientPrepareNewFlowForMagicIP(m netip.Addr) (ClientFlowRef, bool, error) {
	ref, err := c.client.prepareNewFlowForMagicIP(m)
	if err == nil {
		return ref, true, nil
	}
	if errors.Is(err, ErrTransitIPNotRoutable) {
		return ClientFlowRef{}, false, err
	}
	cfg, ok := c.getConfig()
	if !ok {
		return ClientFlowRef{}, false, nil
	}
	if !cfg.ipSets.v4Magic.Contains(m) && !cfg.ipSets.v6Magic.Contains(m) {
		return ClientFlowRef{}, false, nil
	}
	return ClientFlowRef{}, false, ErrUnmappedMagicIP
}

// ConnectorRealIPForTransitIPConnection implements [Conn25Datapath].
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
		e.conn25.client.shutdown()
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
	resp := e.conn25.handleConnectorTransitIPRequest(h.Peer(), h.PeerCaps(), req)
	bs, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
	w.Write(bs)
}

func (c *Conn25) handleHookReplyToDNSQueries(h ipnlocal.PeerAPIHandler, r *http.Request) (sourceAllowed bool, nameAllowed ipnlocal.DNSNameFilter) {
	if !c.prefsAdvertiseConnector.Load() {
		// We are not a connector.
		return false, nil
	}

	cfg, isConfigured := c.getConfig()
	if !isConfigured {
		// We have no connector config.
		return false, nil
	}

	// Determine which app the query is for
	var app appctype.AppConnectorAttr
	if appName, hasApp := r.URL.Query()["app"]; !hasApp || len(appName) != 1 {
		return false, nil
	} else {
		a, ok := cfg.appsByName[appName[0]]
		if !ok {
			// We have no config for the requested app.
			return false, nil
		}
		app = a
	}

	if !cfg.selfAppNames.Contains(app.Name) {
		// We are not a connector for the requested app.
		return false, nil
	}

	if !h.PeerCaps().HasCapability(peercap.Conn25Prefix.ToAttribute(app.Name)) {
		// The peer does not have access to the requested app.
		return false, nil
	}

	return true, makeNameChecker(app)
}

func makeNameChecker(app appctype.AppConnectorAttr) ipnlocal.DNSNameFilter {
	// TODO(tailscale/corp#40076): optimize the comparison; if the func is
	// generated when the app config is created, that will avoid allocating
	// temporary instances. Some of the work (e.g. conversion to [dnsname.FQDN])
	// can also be precomputed.
	return func(name string) bool {
		fqdn, err := dnsname.ToFQDN(strings.ToLower(name))
		if err != nil {
			return false
		}
		for _, domain := range app.Domains {
			appFQDN, err := dnsname.ToFQDN(strings.TrimPrefix(strings.ToLower(domain), "*."))
			if err != nil {
				continue
			}
			// Allow both exact matches and suffix matches, even when the app
			// does not specify a wildcard. This is because of limitations in
			// the Split DNS implementation: we treat all split DNS rules as
			// wildcard even when the app specifies exact matching. The conn25
			// client will only perform address mapping for more strictly
			// matched names but the connector needs to allow queries for any
			// subdomain of an exact match.
			if appFQDN.Contains(fqdn) {
				return true
			}
		}
		return false
	}
}

// onSelfChange implements the [ipnext.Hooks.OnSelfChange] hook.
func (e *extension) onSelfChange(selfNode tailcfg.NodeView) {
	cfg, err := configFromNodeView(selfNode)
	if err != nil {
		e.conn25.logf("error generating config from self node view: %v", err)
		return
	}
	// Store the routes only once the config parsed, so a bad self node
	// leaves the previous routes and config in place together.
	e.conn25.appDNSRoutes.Store(cfg.appDNSRoutes())
	e.conn25.reconfig(cfg)
}

// profileStateChange implements the [ipnext.Hooks.ProfileStateChange] hook.
func (e *extension) profileStateChange(loginProfile ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	e.conn25.prefsAdvertiseConnector.Store(prefs.AppConnector().Advertise)

	if !sameNode {
		// Load an empty configuration to disable conn25 entirely, since we
		// don't yet know that it is configured on the new profile. We will
		// know once [extension.onSelfChange] is called with a new
		// configuration, if any.
		e.conn25.reconfig(&config{})
		e.conn25.appDNSRoutes.Store(nil)

		// If a client changes profiles and becomes a different node, all of its
		// existing flows lose meaning, and we should delete them so that the
		// settings of our new environment can take over.
		if e.clearAllDatapathFlows != nil {
			e.clearAllDatapathFlows()
		}

		// Clear internal state, like address assignments for clients and
		// transit IP mappings for connectors.
		e.conn25.client.reset()
		e.conn25.connector.reset()
	}
}

func (e *extension) extraWireGuardAllowedIPs(id tailcfg.NodeID) views.Slice[netip.Prefix] {
	return e.conn25.client.extraWireGuardAllowedIPs(id)
}

// Conn25 holds state for routing traffic for a domain via a connector.
type Conn25 struct {
	config                  atomic.Pointer[config]
	prefsAdvertiseConnector atomic.Bool

	// appDNSRoutes holds the split DNS routes for the app domains in the
	// self node's capabilities, as returned by [config.appDNSRoutes]. It is
	// recomputed on each self node change and served to
	// [ipnext.Hooks.ExtraDNSRoutes]. The map must not be mutated once stored.
	appDNSRoutes syncs.AtomicValue[map[string][]*dnstype.Resolver]

	logf      logger.Logf
	client    *client
	connector *connector
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
		logf: logf,
	}
	getIPSets := func() ipSets {
		cfg, ok := c.getConfig()
		if !ok {
			return emptyIPSets()
		}
		return cfg.ipSets
	}
	c.config.Store(&config{}) // initialize with empty to avoid nil checks
	c.client = &client{
		logf:        logf,
		addrsCh:     make(chan addrs, 64),
		assignments: addrAssignments{clock: tstime.StdClock{}},
		getIPSets:   getIPSets,
		generation:  1, // initialize with non-zero value to detect missing stamps
	}
	c.connector = &connector{
		logf:        logf,
		getIPSets:   getIPSets,
		clock:       tstime.StdClock{},
		expiryQueue: list.New(),
		tokenSecret: newTokenSecret(),
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

const (
	dupeTransitIPMessage            = "Duplicate transit address in ConnectorTransitIPRequest"
	noMatchingPeerIPFamilyMessage   = "No peer IP found with matching IP family"
	addrFamilyMismatchMessage       = "Transit and Destination addresses must have matching IP family"
	unknownAppNameMessage           = "The App name in the request does not match a configured App"
	missingAppPermissionMessage     = "You do not have permission to use this App"
	unparseableAppPermissionMessage = "The permission granting access to this App could not be parsed"
	transitIPNotInPoolMessage       = "The transit address is not in a configured transit IP pool"
	disallowedDestinationMessage    = "Destination address is in a disallowed address range"
	invalidTokenMessage             = "The destination IP token is missing or did not verify"
)

// handleConnectorTransitIPRequest creates a ConnectorTransitIPResponse in response
// to a ConnectorTransitIPRequest. It updates the connectors mapping of
// TransitIP->DestinationIP per peer (using the Peer's IP that matches the address
// family of the transitIP). If a peer has stored this mapping in the connector,
// Conn25 will route traffic to TransitIPs to DestinationIPs for that peer.
func (c *Conn25) handleConnectorTransitIPRequest(n tailcfg.NodeView, peerCaps tailcfg.PeerCapMap, ctipr ConnectorTransitIPRequest) ConnectorTransitIPResponse {
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
		token, err := base64.StdEncoding.DecodeString(each.Token)
		if err != nil || !c.connector.verifyToken(token, each.App, each.DestinationIP) {
			resp.TransitIPs = append(resp.TransitIPs, TransitIPResponse{
				Code:    InvalidDestinationIPToken,
				Message: invalidTokenMessage,
			})
			continue
		}

		// Canonicalize IPv4-in-IPv6 addresses, so that duplicate detection and
		// the keys we store in the connector's map match the unmapped form the
		// datapath produces when it parses packets.
		each.TransitIP = each.TransitIP.Unmap()
		each.DestinationIP = each.DestinationIP.Unmap()

		if seen[each.TransitIP] {
			resp.TransitIPs = append(resp.TransitIPs, TransitIPResponse{
				Code:    DuplicateTransitIP,
				Message: dupeTransitIPMessage,
			})
			c.logf("[Unexpected] peer attempt to map a transit IP reused a transitIP: node: %s, IP: %v",
				n.StableID(), each.TransitIP)
			continue
		}

		// The grant that gives the peer access to the app also carries the
		// protocols and ports it may use, which get stored with the mapping
		// and enforced on every packet by [connector.ingressAllow].
		//
		// TODO(mzb): cache this per peer+app so that every transit IP a peer
		// registers for an app shares one [views.Slice], rather than each
		// registration decoding and storing its own copy.
		ports, hasCap, err := appProtoPortRanges(peerCaps, each.App)
		if !hasCap {
			resp.TransitIPs = append(resp.TransitIPs, TransitIPResponse{
				Code:    MissingAppPermission,
				Message: missingAppPermissionMessage,
			})
			continue
		}
		if err != nil {
			// Fail closed on the whole grant rather than registering a
			// mapping under the values we did manage to understand.
			resp.TransitIPs = append(resp.TransitIPs, TransitIPResponse{
				Code:    UnparseableAppPermission,
				Message: unparseableAppPermissionMessage,
			})
			c.logf("[Unexpected] peer holds an unparseable conn25 grant: node: %s, app: %q, err: %v",
				n.StableID(), each.App, err)
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
		tipresp := c.connector.handleTransitIPRequest(n, peerIPv4, peerIPv6, each, ports)
		seen[each.TransitIP] = true
		resp.TransitIPs = append(resp.TransitIPs, tipresp)
	}
	return resp
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

	// Token is supplied by the connector in its PeerAPI DoH response. It should
	// not be modified, and shouldn't need to be inspected. It should be
	// sent back to the connector in this request for the DestinationIP
	// and App for which it was originally received.
	Token string `json:"token,omitzero"`
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

	// MissingAppPermission indicates that the client is not permitted to access
	// the App name that was specified in the request.
	MissingAppPermission = 6

	// TransitIPNotInPool indicates that the transit address in the request is
	// not within a transit IP pool the connector is configured with. A client
	// which sees this has most likely allocated from a pool configuration that
	// the connector has not received yet, or has already replaced.
	TransitIPNotInPool = 7

	// DisallowedDestination indicates that the destination IP address is not
	// allowed (including but not limited to loopback, Tailscale, link-local,
	// and private addresses, along with addresses within the configured magic and
	// transit IP pools).
	DisallowedDestination = 8

	// InvalidDestinationIPToken indicates that the request's token did not
	// authenticate, or there was no token provided.
	InvalidDestinationIPToken = 9

	// UnparseableAppPermission indicates that the client holds a permission for
	// the App name in the request, but the connector could not parse the
	// protocols and ports it grants and so refused the request rather than
	// registering a mapping it would enforce incorrectly. Unlike
	// [MissingAppPermission] this is a misconfiguration of the grant itself,
	// which the client cannot resolve by asking for a different App.
	UnparseableAppPermission = 10
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

const (
	AppConnectorAttrName                     = "tailscale.com/app-connectors"
	AppConnectorsExperimentalIPPoolsAttrName = "tailscale.com/app-connectors-experimental-ippools"

	// DNSAddrScheme is the custom URI scheme used for conn25-managed split DNS
	// entries to determine the destination at query time rather than configuration
	// time.
	DNSAddrScheme = "tailscale-app"
)

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
	apps               []appctype.AppConnectorAttr
	appsByName         map[string]appctype.AppConnectorAttr
	appNamesByDomain   map[dnsname.FQDN][]string
	appNamesByWCDomain map[dnsname.FQDN][]string
	selfAppNames       set.Set[string]
	ipSets             ipSets
}

func configFromNodeView(n tailcfg.NodeView) (*config, error) {
	// conn25 apps are provided under [AppConnectorAttrName] with the Mode
	// field set to "magicip".
	unfilteredApps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](n.CapMap(), AppConnectorAttrName)
	if err != nil {
		return &config{}, err
	}
	var apps []appctype.AppConnectorAttr
	for _, app := range unfilteredApps {
		if app.Mode == appctype.MagicIP {
			apps = append(apps, app)
		}
	}
	if len(apps) == 0 {
		return &config{}, nil
	}
	poolsSlice, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.Conn25PoolsAttr](n.CapMap(), AppConnectorsExperimentalIPPoolsAttrName)
	if err != nil {
		return &config{}, err
	}
	if len(poolsSlice) != 1 {
		return &config{}, errors.New("must be one conn25 pools nodeattr")
	}
	pools := poolsSlice[0]
	selfTags := set.SetOf(n.Tags().AsSlice())
	cfg := &config{
		isConfigured:       true,
		apps:               apps,
		appsByName:         map[string]appctype.AppConnectorAttr{},
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

	v4Mipp, err := ipSetFromIPRanges(pools.V4MagicIPPool)
	if err != nil {
		return &config{}, err
	}
	v4Tipp, err := ipSetFromIPRanges(pools.V4TransitIPPool)
	if err != nil {
		return &config{}, err
	}
	v6Mipp, err := ipSetFromIPRanges(pools.V6MagicIPPool)
	if err != nil {
		return &config{}, err
	}
	v6Tipp, err := ipSetFromIPRanges(pools.V6TransitIPPool)
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
	return cfg, nil
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

// appDNSRoutes returns split DNS routes, keyed by domain suffix, for the app
// domains in cfg. Each route resolves via the [DNSAddrScheme] scheme naming
// the app, so the connector that serves it is chosen at query time. It
// returns nil if cfg is not configured.
func (cfg *config) appDNSRoutes() map[string][]*dnstype.Resolver {
	if !cfg.isConfigured {
		return nil
	}
	m := make(map[string][]*dnstype.Resolver, len(cfg.appNamesByDomain)+len(cfg.appNamesByWCDomain))
	add := func(byDomain map[dnsname.FQDN][]string) {
		for domain, appNames := range byDomain {
			if len(appNames) == 0 {
				continue
			}
			// In the case of multiple apps specifying the same domain (which is misconfiguration
			// that should be validated at point of input), the last one in the config list wins.
			appName := appNames[len(appNames)-1]
			m[domain.WithoutTrailingDot()] = []*dnstype.Resolver{{Addr: fmt.Sprintf("%s:%s", DNSAddrScheme, appName), UseWithExitNode: true}}
		}
	}
	// If an exact and a wildcard domain coincide, the exact domain's app
	// takes the route, so add it last.
	add(cfg.appNamesByWCDomain)
	add(cfg.appNamesByDomain)
	return m
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
	if !e.conn25.client.assignmentIsCurrent(as) {
		e.conn25.logf("stale address assignment, skipping it")
		return nil
	}
	err := e.sendAddressAssignment(ctx, as)
	if err != nil {
		return err
	}
	err = e.conn25.client.addTransitIPForConnector(as)
	if err != nil {
		if errors.Is(err, errStaleGeneration) {
			e.conn25.logf("stale address assignment, dropping it")
			return nil
		}
		return err
	}

	e.host.AuthReconfigAsync()
	return nil
}

func makePeerAPIReq(ctx context.Context, httpClient *http.Client, urlBase string, as addrs) error {
	url := urlBase + "/v0/connector/transit-ip"

	reqBody := ConnectorTransitIPRequest{
		TransitIPs: []TransitIPRequest{{
			TransitIP:     as.connectorAddr.transit,
			DestinationIP: as.dst,
			App:           as.app,
			Token:         as.connectorAddr.token,
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

func (e *extension) pickConnectorURLBase(app appctype.AppConnectorAttr) string {
	nb := e.host.NodeBackend()
	rp := e.getRouteCheckReport()
	peers := pickConnector(nb, app, rp)
	for _, p := range peers {
		if urlBase := nb.PeerAPIBase(p); urlBase != "" {
			return urlBase
		}
	}
	return ""
}

// sendAddressAssignment registers the TransitIP in as with the connector in as,
// which is the connector that sent the DNS response with the destination IP in as.
func (e *extension) sendAddressAssignment(ctx context.Context, as addrs) error {
	urlBase := e.host.NodeBackend().PeerAPIBase(as.connectorAddr.node)
	if urlBase == "" {
		return fmt.Errorf("no PeerAPI URL base found for node stable ID %q", as.connectorAddr.node.StableID())
	}
	client := e.backend.Sys().Dialer.Get().PeerAPIHTTPClient()
	return makePeerAPIReq(ctx, client, urlBase, as)
}

type dnsResponseRewrite struct {
	domain        dnsname.FQDN
	dst           netip.Addr
	ttlSeconds    uint32
	connectorNode tailcfg.NodeView
	token         string
}

func (p *dnsResponseParser) makeServFail(logf logger.Logf) []byte {
	h := p.hdr
	h.Response = true
	h.Authoritative = true
	h.RCode = dnsmessage.RCodeServerFailure
	b := dnsmessage.NewBuilder(nil, h)
	err := b.StartQuestions()
	if err != nil {
		logf("error making servfail: %v", err)
		return []byte{}
	}
	err = b.Question(p.question)
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

var (
	// metricDNSResponseRewriteErrorServfail increments servfail returns
	// on an error rewriting response for an app connector domain.
	metricDNSResponseRewriteErrorServfail = clientmetric.NewCounter(
		"conn25_map_dns_response_rewrite_error_servfail",
	)

	// metricDNSResponseSkippedAAAA4In6 increments when an AAAA answer for an
	// app connector domain is dropped because it holds an IPv4-in-IPv6 address.
	metricDNSResponseSkippedAAAA4In6 = clientmetric.NewCounter(
		"conn25_map_dns_response_skipped_aaaa_4in6",
	)
)

// Question types whose upstream answers we write through instead of rewriting or dropping them.
var passThroughQuestionTypes = set.Of(
	// Types used for Email traffic.
	dnsmessage.TypeMX,
	dnsmessage.TypeTXT,

	// Types used for VOIP traffic.
	dnsmessage.TypeSRV,
	dnsmessage.Type(35), // NAPTR
)

// connectorAddr is everything an [addrs] needs in order to register itself
// with a connector: the transit address allocated for it, the connector that
// answered the DNS query it came from, and the token that connector issued for
// the destination address.
type connectorAddr struct {
	transit netip.Addr
	node    tailcfg.NodeView
	// token is opaque to the client. See [TokenHeader] and
	// [TransitIPRequest.Token]. If it is empty, the connector
	// did not issue one.
	token string
}

func validateAndGetQuestion(questions []dnsmessage.Question) (dnsmessage.Question, bool) {
	// Any message we are interested in has one question (RFC 9619)
	if len(questions) != 1 {
		return dnsmessage.Question{}, false
	}
	question := questions[0]
	// The other Class types are not commonly used and supporting them hasn't been considered.
	if question.Class != dnsmessage.ClassINET {
		return dnsmessage.Question{}, false
	}
	// Write through record types we are sure are unrelated to conn25, as we try our best not to break
	// user's application. If this causes problems in the future, it could be reasonable to not write through anything.
	if passThroughQuestionTypes.Contains(question.Type) {
		return dnsmessage.Question{}, false
	}
	return question, true
}

// dnsResponseParser uses a dnsmessage.Parser to process a DNS response.
// conn25 observes the DoH DNS responses on this client and dnsResponseParser
// checks whether the response is something conn25 is interested in (valid,
// for a domain we're configured for) and then can follow the cname chain and
// resolve a map of domain -> address in a conn25 canonical way.
type dnsResponseParser struct {
	p             *dnsmessage.Parser
	queriedDomain dnsname.FQDN
	hdr           dnsmessage.Header
	question      dnsmessage.Question
}

func parseQuestion(buf []byte) (*dnsResponseParser, bool) {
	parseResult := &dnsResponseParser{}
	var p dnsmessage.Parser
	hdr, err := p.Start(buf)
	if err != nil {
		return nil, false
	}
	parseResult.hdr = hdr
	parseResult.p = &p

	questions, err := p.AllQuestions()
	if err != nil {
		return nil, false
	}
	question, ok := validateAndGetQuestion(questions)
	if !ok {
		return nil, false
	}
	parseResult.question = question

	queriedDomain, err := normalizeDNSName(question.Name.String())
	if err != nil {
		return nil, false
	}
	if queriedDomain == "" {
		return nil, false
	}
	parseResult.queriedDomain = queriedDomain
	return parseResult, true
}

func matchToApp(queriedDomain dnsname.FQDN, cfg *config, prefsAdvertiseConnector bool) (string, bool) {
	if queriedDomain == "" {
		return "", false
	}
	appNames := cfg.getAppsForConnectorDomain(queriedDomain, prefsAdvertiseConnector)
	if len(appNames) == 0 {
		// There's no apps covering this domain.
		return "", false
	}
	// There is guaranteed to be at least one matching app, so just take the first one for now
	// TODO(tailscale/corp#50408): We have access to res.DoHMeta.RequestURL, so we can easily see the requested
	// app name. So we can make sure we have that configured, bail if not, and use that instead
	// of just taking the first one. We can also verify the connector node advertises the app in its
	// CapMap.
	appName := appNames[0]
	return appName, true
}

type addrTTL struct {
	a   netip.Addr
	ttl uint32
}

func (p *dnsResponseParser) resolveAnswers() ([]addrTTL, error) {
	resolvedAnswers := []addrTTL{}
	if p.question.Type != dnsmessage.TypeA && p.question.Type != dnsmessage.TypeAAAA {
		return resolvedAnswers, nil
	}
	// Question Type A/AAAA
	var cnameChain map[dnsname.FQDN]dnsname.FQDN
	for {
		h, err := p.p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		// other classes are unsupported, and we checked the question was for ClassINET already
		if h.Class != dnsmessage.ClassINET {
			if err := p.p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		switch h.Type {
		case dnsmessage.TypeCNAME:
			// A DNS response with CNAME records might look a bit like
			//
			// a.example.com. CNAME b.example.com.
			// b.example.com. CNAME example.com.
			// example.com. A 1.1.1.1
			//
			// We don't return CNAME records for our domains. We use them to build a
			// cname chain so we can rewrite the final A/AAAA record to eg:
			//
			// a.example.com A (some magic IP that is associated with 1.1.1.1)
			r, err := p.p.CNAMEResource()
			if err != nil {
				return nil, err
			}
			src, err := normalizeDNSName(h.Name.String())
			if err != nil {
				return nil, err
			}
			target, err := normalizeDNSName(r.CNAME.String())
			if err != nil {
				return nil, err
			}
			mak.Set(&cnameChain, src, target)
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			if h.Type != p.question.Type {
				// would not expect a v4 response to a v6 question or vice versa, don't add a rewrite for this.
				if err := p.p.SkipAnswer(); err != nil {
					return nil, err
				}
				continue
			}
			answerDomain, err := normalizeDNSName(h.Name.String())
			if err != nil {
				return nil, err
			}
			// If answerDomain is not the same domain as the domain that was queried for,
			// try to walk down the cname chain from the queried domain until we find the answerDomain.
			// If we can't, skip the answer.
			// If we can, then we will rewrite the dns response to an A/AAAA record pointing
			// the queriedDomain to the magic IP.
			if answerDomain != p.queriedDomain {
				d := p.queriedDomain
				found := false
				seen := set.Set[dnsname.FQDN]{} // avoid following cname record loops
				for {
					target, ok := cnameChain[d]
					if !ok || seen.Contains(target) {
						break
					}
					if target == answerDomain {
						found = true
						break
					}
					seen.Add(target)
					d = target
				}
				if !found {
					if err := p.p.SkipAnswer(); err != nil {
						return nil, err
					}
					continue
				}
			}
			var dstAddr netip.Addr
			if h.Type == dnsmessage.TypeA {
				r, err := p.p.AResource()
				if err != nil {
					return nil, err
				}
				dstAddr = netip.AddrFrom4(r.A)
			} else {
				r, err := p.p.AAAAResource()
				if err != nil {
					return nil, err
				}
				dstAddr = netip.AddrFrom16(r.AAAA)

				// Skip AAAA answer with IPv4-in-IPv6 address.
				if dstAddr.Is4In6() {
					metricDNSResponseSkippedAAAA4In6.Add(1)
					continue
				}
			}
			resolvedAnswers = append(resolvedAnswers, addrTTL{a: dstAddr, ttl: h.TTL})
		default:
			// we already checked the question was for a supported type, this answer is unexpected
			if err := p.p.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}
	return resolvedAnswers, nil
}

// mapDNSResponse parses and inspects the DNS response. If the domain
// is determined to belong to app this node is client for, it assigns addresses
// for connecting and rewrites the response to contain Magic IPs.
func (e *extension) mapDNSResponse(res *resolver.Response) []byte {
	c := e.conn25
	buf := res.Bs
	// If there's no DoH metadata, we know this response didn't come
	// from a connector's PeerAPI DoH.
	if res.DoHMeta == nil {
		return buf
	}
	cfg, ok := c.getConfig()
	if !ok {
		return buf
	}
	prefsAdvertiseConnector := c.prefsAdvertiseConnector.Load()

	parser, ok := parseQuestion(buf)
	if !ok {
		return buf
	}

	appName, ok := matchToApp(parser.queriedDomain, cfg, prefsAdvertiseConnector)
	if !ok {
		return buf
	}

	// We've determined this is a conn25 concern. From now on if we can't rewrite
	// the response we servfail.

	if parser.question.Type == dnsmessage.TypeHTTPS {
		newBuf, err := rewriteHTTPSResponse(parser.hdr, parser.question, parser.p)
		if err != nil {
			metricDNSResponseRewriteErrorServfail.Add(1)
			c.logf("error rewriting HTTPS dns response: %v", err)
			return parser.makeServFail(c.logf)
		}
		return newBuf
	}

	resolvedAnswers, err := parser.resolveAnswers()
	if err != nil {
		return parser.makeServFail(c.logf)
	}

	var answers []dnsResponseRewrite
	if len(resolvedAnswers) > 0 {
		tokens := tokensFromHeader(res.DoHMeta.ResponseHeader)
		connectorNode, err := e.extractConnectorFromRequestURL(res.DoHMeta.RequestURL)
		if err != nil {
			c.logf("could not identify the connector that answered a DNS query: %v", err)
			// TODO(fran) this should be servfail
			return buf
		}
		for _, ans := range resolvedAnswers {
			// The connector may or may not send a token.
			// If it doesn't, we don't want to bail.
			// If it does, it may require that the token
			// be sent back in the TransitIPRequest.
			token := tokens[ans.a]

			answers = append(answers, dnsResponseRewrite{
				domain:        parser.queriedDomain,
				dst:           ans.a,
				ttlSeconds:    ans.ttl,
				connectorNode: connectorNode,
				token:         token,
			})
		}
	}

	newBuf, err := c.client.rewriteDNSResponse(appName, parser.hdr, parser.question, answers)
	if err != nil {
		metricDNSResponseRewriteErrorServfail.Add(1)
		c.logf("error rewriting dns response: %v", err)
		return parser.makeServFail(c.logf)
	}
	return newBuf
}

// rewriteHTTPSResponse writes through the HTTPS (type 65) answers in a DNS
// response, stripping the ipv4hint/ipv6hint SvcParams (not obvious if we
// should replace with magic IPs). p must be positioned at the start of the
// answer section (i.e. questions already consumed). The additional section is
// dropped.
func rewriteHTTPSResponse(hdr dnsmessage.Header, question dnsmessage.Question, p *dnsmessage.Parser) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(question); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Type != dnsmessage.TypeHTTPS {
			// Only HTTPS records are expected in an HTTPS response; drop anything else.
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		r, err := p.HTTPSResource()
		if err != nil {
			return nil, err
		}
		r.DeleteParam(dnsmessage.SVCParamIPv4Hint)
		r.DeleteParam(dnsmessage.SVCParamIPv6Hint)
		if err := b.HTTPSResource(h, r); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func (e *extension) getRouteCheckReport() ipnlocal.RouteCheckReport {
	b, ok := e.backend.(*ipnlocal.LocalBackend)
	if !ok {
		return nil
	}
	hook := ipnlocal.HookRouteCheckReport.GetOrNil()
	if hook == nil {
		return nil
	}
	return hook(b)
}

func peerIsReachable(rp ipnlocal.RouteCheckReport, n tailcfg.NodeView) bool {
	if rp == nil {
		return n.Online().Get()
	}
	return rp.IsReachable(n.ID()).IsReachable()
}

func isPeerEligibleConnector(peer tailcfg.NodeView) bool {
	if !peer.Valid() || !peer.Hostinfo().Valid() {
		return false
	}
	isConn, _ := peer.Hostinfo().AppConnector().Get()
	return isConn
}

func sortByPreference(self tailcfg.NodeView, ns []tailcfg.NodeView) {
	// The ordering of the nodes is semantic (callers use the first node they can
	// get a peer api url for).
	if !self.Valid() {
		return
	}
	scores := traffic.ScoresFor(self.ID(), ns)
	scores.SortNodes(ns)
}

// pickConnector returns peers the backend knows about that match the app, in order of preference to use as
// a connector.
func pickConnector(nb ipnext.NodeBackend, app appctype.AppConnectorAttr, routecheckReport ipnlocal.RouteCheckReport) []tailcfg.NodeView {
	appTagsSet := set.SetOf(app.Connectors)
	matches := nb.AppendMatchingPeers(nil, func(n tailcfg.NodeView) bool {
		if !isPeerEligibleConnector(n) {
			return false
		}
		if !peerIsReachable(routecheckReport, n) {
			return false
		}
		for _, t := range n.Tags().All() {
			if appTagsSet.Contains(t) {
				return true
			}
		}
		return false
	})
	sortByPreference(nb.Self(), matches)
	return matches
}

// extractConnectorFromRequestURL returns the peer whose Tailscale address is
// the host of u, the PeerAPI DoH URL that a DNS response came back from.
//
// That peer is the connector which answered the query, and so is the only peer
// that will accept the tokens in that response (see [TokenHeader]).
func (e *extension) extractConnectorFromRequestURL(u *url.URL) (tailcfg.NodeView, error) {
	if u == nil {
		return tailcfg.NodeView{}, errors.New("nil URL in PeerAPI DoH request")
	}
	nodeAddr, err := netip.ParseAddr(u.Hostname())
	if err != nil {
		return tailcfg.NodeView{}, err
	}

	nodeID, ok := e.host.NodeBackend().NodeByAddr(nodeAddr)
	if !ok {
		return tailcfg.NodeView{}, fmt.Errorf("did not find node ID for peer IP addr: %s", nodeAddr.String())
	}

	node, ok := e.host.NodeBackend().NodeByID(nodeID)
	if !ok {
		return tailcfg.NodeView{}, fmt.Errorf("did not find node with ID: %d", nodeID)
	}

	return node, nil
}

// TokenHeader is the PeerAPI DoH response header a connector uses to hand a
// client a token for each address it answered with. One header line is sent
// per A/AAAA answer, formatted as:
//
//	Tailscale-Conn25-Token: <ip> <token>
//
// The ip is the correlation key the client uses to match each token
// to the answer it belongs to in the DNS response body.
// The token itself is opaque to the client; see [TransitIPRequest.Token].
const TokenHeader = "Tailscale-Conn25-Token"

// tokensFromHeader returns the tokens in hdr, keyed by the address each one was
// issued for. See [TokenHeader] for the format.
func tokensFromHeader(hdr http.Header) map[netip.Addr]string {
	var tokens map[netip.Addr]string
	for _, line := range hdr.Values(TokenHeader) {
		addrStr, token, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || token == "" || strings.Contains(token, " ") {
			continue
		}
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			continue
		}
		mak.Set(&tokens, addr, token)
	}
	return tokens
}

func handleHookPeerAPIDNSResponse(h ipnlocal.PeerAPIHandler, r *http.Request, pr *ipnlocal.PeerAPIDNSResponse) {
	e, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		return
	}
	if !e.conn25.isConfigured() {
		return
	}
	e.conn25.mintTokensForDNSResponse(h, r, pr)
}

// mintTokensForDNSResponse mints a destination IP token for each A/AAAA answer
// in the DoH response pr, and writes them as [TokenHeader] header lines.
func (c *Conn25) mintTokensForDNSResponse(h ipnlocal.PeerAPIHandler, r *http.Request, pr *ipnlocal.PeerAPIDNSResponse) {
	// handleHookReplyToDNSQueries is called by connectors before forwarding the
	// DNS request upstream. But it's possible for a connector to forward a DNS
	// request upstream for other reasons also, so we must call it again here and
	// check this DNS request is something we should route for conn25 (we are a
	// connector for the requested app, the netmap says the peer may use the app,
	// and that the app named in the HTTP query parameter contains the domain in
	// the DNS query.)
	sourceAllowed, nameAllowed := c.handleHookReplyToDNSQueries(h, r)
	if !sourceAllowed {
		return
	}
	parser, ok := parseQuestion(pr.Raw)
	if !ok {
		return
	}
	if !nameAllowed(parser.queriedDomain.WithTrailingDot()) {
		return
	}
	answers, err := parser.resolveAnswers()
	if err != nil {
		return
	}
	// checked to have len == 1 in handleHookReplyToDNSQueries
	appName := r.URL.Query()["app"][0]
	for _, answer := range answers {
		token, err := c.connector.mintToken(appName, answer.a)
		if err != nil {
			c.logf("error minting destination IP token: %v", err)
			continue
		}
		pr.Header.Add(TokenHeader, answer.a.String()+" "+base64.StdEncoding.EncodeToString(token))
	}
}
