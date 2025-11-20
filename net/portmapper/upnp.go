// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

// (no raw sockets in JS/WASM)

package portmapper

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tailscale/goupnp"
	"github.com/tailscale/goupnp/dcps/internetgateway2"
	"github.com/tailscale/goupnp/soap"
	"tailscale.com/envknob"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

// References:
//
// WANIP Connection v2: http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf

// upnpMapping is a port mapping over the upnp protocol. After being created it is immutable,
// but the client field may be shared across mapping instances.
type upnpMapping struct {
	gw         netip.Addr
	external   netip.AddrPort
	internal   netip.AddrPort
	goodUntil  time.Time
	renewAfter time.Time

	// rootDev is the UPnP root device, and may be reused across different
	// UPnP mappings.
	rootDev *goupnp.RootDevice
	// loc is the location used to fetch the rootDev
	loc *url.URL
	// client is the most recent UPnP client used, and should only be used
	// to release an existing mapping; new mappings should be selected from
	// the rootDev on each attempt.
	client upnpClient
}

// upnpProtocolUDP represents the protocol name for UDP, to be used in the UPnP
// <AddPortMapping> message in the <NewProtocol> field.
//
// NOTE: this must be an upper-case string, or certain routers will reject the
// mapping request. Other implementations like miniupnp send an upper-case
// protocol as well. See:
//
//	https://github.com/tailscale/tailscale/issues/7377
const upnpProtocolUDP = "UDP"

func (u *upnpMapping) MappingType() string      { return "upnp" }
func (u *upnpMapping) GoodUntil() time.Time     { return u.goodUntil }
func (u *upnpMapping) RenewAfter() time.Time    { return u.renewAfter }
func (u *upnpMapping) External() netip.AddrPort { return u.external }
func (u *upnpMapping) MappingDebug() string {
	return fmt.Sprintf("upnpMapping{gw:%v, external:%v, internal:%v, renewAfter:%d, goodUntil:%d, loc:%q}",
		u.gw, u.external, u.internal,
		u.renewAfter.Unix(), u.goodUntil.Unix(),
		u.loc)
}
func (u *upnpMapping) Release(ctx context.Context) {
	u.client.DeletePortMapping(ctx, "", u.external.Port(), upnpProtocolUDP)
}

// upnpClient is an interface over the multiple different clients exported by goupnp,
// exposing the functions we need for portmapping. Those clients are auto-generated from XML-specs,
// which is why they're not very idiomatic.
type upnpClient interface {
	AddPortMapping(
		ctx context.Context,

		// remoteHost is the remote device sending packets to this device, in the format of x.x.x.x.
		// The empty string, "", means any host out on the internet can send packets in.
		remoteHost string,

		// externalPort is the exposed port of this port mapping. Visible during NAT operations.
		// 0 will let the router select the port, but there is an additional call,
		// `AddAnyPortMapping`, which is available on 1 of the 3 possible protocols,
		// which should be used if available. See `addAnyPortMapping` below, which calls this if
		// `AddAnyPortMapping` is not supported.
		externalPort uint16,

		// protocol is whether this is over TCP or UDP. Either "TCP" or "UDP".
		protocol string,

		// internalPort is the port that the gateway device forwards the traffic to.
		internalPort uint16,
		// internalClient is the IP address that packets will be forwarded to for this mapping.
		// Internal client is of the form "x.x.x.x".
		internalClient string,

		// enabled is whether this portmapping should be enabled or disabled.
		enabled bool,
		// portMappingDescription is a user-readable description of this portmapping.
		portMappingDescription string,
		// leaseDurationSec is the duration of this portmapping. The value of this argument must be
		// greater than 0. From the spec, it appears if it is set to 0, it will switch to using
		// 604800 seconds, but not sure why this is desired. The recommended time is 3600 seconds.
		leaseDurationSec uint32,
	) error

	DeletePortMapping(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
	GetExternalIPAddress(ctx context.Context) (externalIPAddress string, err error)
	GetStatusInfo(ctx context.Context) (status string, lastConnError string, uptime uint32, err error)
}

// tsPortMappingDesc gets sent to UPnP clients as a human-readable label for the portmapping.
// It is not used for anything other than labelling.
const tsPortMappingDesc = "tailscale-portmap"

// addAnyPortMapping abstracts over different UPnP client connections, calling
// the available AddAnyPortMapping call if available for WAN IP connection v2,
// otherwise picking either the previous port (if one is present) or a random
// port and trying to obtain a mapping using AddPortMapping.
//
// It returns the new external port (which may not be identical to the external
// port specified), or an error.
//
// TODO(bradfitz): also returned the actual lease duration obtained. and check it regularly.
func addAnyPortMapping(
	ctx context.Context,
	upnp upnpClient,
	externalPort uint16,
	internalPort uint16,
	internalClient string,
	leaseDuration time.Duration,
) (newPort uint16, err error) {
	// Some devices don't let clients add a port mapping for privileged
	// ports (ports below 1024). Additionally, per section 2.3.18 of the
	// UPnP spec, regarding the ExternalPort field:
	//
	//    If this value is specified as a wildcard (i.e. 0), connection
	//    request on all external ports (that are not otherwise mapped)
	//    will be forwarded to InternalClient. In the wildcard case, the
	//    value(s) of InternalPort on InternalClient are ignored by the IGD
	//    for those connections that are forwarded to InternalClient.
	//    Obviously only one such entry can exist in the NAT at any time
	//    and conflicts are handled with a “first write wins” behavior.
	//
	// We obviously do not want to open all ports on the user's device to
	// the internet, so we want to do this prior to calling either
	// AddAnyPortMapping or AddPortMapping.
	//
	// Pick an external port that's greater than 1024 by getting a random
	// number in [0, 65535 - 1024] and then adding 1024 to it, shifting the
	// range to [1024, 65535].
	if externalPort < 1024 {
		externalPort = uint16(rand.N(65535-1024) + 1024)
	}

	// First off, try using AddAnyPortMapping; if there's a conflict, the
	// router will pick another port and return it.
	if upnp, ok := upnp.(*internetgateway2.WANIPConnection2); ok {
		return upnp.AddAnyPortMapping(
			ctx,
			"",
			externalPort,
			upnpProtocolUDP,
			internalPort,
			internalClient,
			true,
			tsPortMappingDesc,
			uint32(leaseDuration.Seconds()),
		)
	}

	// Fall back to using AddPortMapping, which requests a mapping to/from
	// a specific external port.
	err = upnp.AddPortMapping(
		ctx,
		"",
		externalPort,
		upnpProtocolUDP,
		internalPort,
		internalClient,
		true,
		tsPortMappingDesc,
		uint32(leaseDuration.Seconds()),
	)
	return externalPort, err
}

// getUPnPRootDevice fetches the UPnP root device given the discovery response,
// ignoring the underlying protocol for now.
// Adapted from https://github.com/huin/goupnp/blob/master/GUIDE.md.
//
// The gw is the detected gateway.
//
// The meta is the most recently parsed UDP discovery packet response
// from the Internet Gateway Device.
func getUPnPRootDevice(ctx context.Context, logf logger.Logf, debug DebugKnobs, gw netip.Addr, meta uPnPDiscoResponse) (rootDev *goupnp.RootDevice, loc *url.URL, err error) {
	if debug.DisableUPnP() {
		return nil, nil, nil
	}

	if meta.Location == "" {
		return nil, nil, nil
	}

	if debug.VerboseLogs {
		logf("fetching %v", meta.Location)
	}
	u, err := url.Parse(meta.Location)
	if err != nil {
		return nil, nil, err
	}

	ipp, err := netip.ParseAddrPort(u.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("unexpected host %q in %q", u.Host, meta.Location)
	}
	if ipp.Addr() != gw {
		// https://github.com/tailscale/tailscale/issues/5502
		logf("UPnP discovered root %q does not match gateway IP %v; repointing at gateway which is assumed to be floating",
			meta.Location, gw)
		u.Host = net.JoinHostPort(gw.String(), u.Port())
	}

	// We're fetching a smallish XML document over plain HTTP
	// across the local LAN, without using DNS.  There should be
	// very few round trips and low latency, so one second is a
	// long time.
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	// This part does a network fetch.
	root, err := goupnp.DeviceByURL(ctx, u)
	if err != nil {
		return nil, nil, err
	}
	return root, u, nil
}

// selectBestService picks the "best" service from the given UPnP root device
// to use to create a port mapping. It may return (nil, nil) if no supported
// service was found in the provided *goupnp.RootDevice.
//
// loc is the parsed location that was used to fetch the given RootDevice.
//
// The provided ctx is not retained in the returned upnpClient, but
// its associated HTTP client is (if set via goupnp.WithHTTPClient).
func selectBestService(ctx context.Context, logf logger.Logf, root *goupnp.RootDevice, loc *url.URL) (client upnpClient, err error) {
	method := "none"
	defer func() {
		if client == nil {
			return
		}
		logf("saw UPnP type %v at %v; %v (%v), method=%s",
			strings.TrimPrefix(fmt.Sprintf("%T", client), "*internetgateway2."),
			loc, root.Device.FriendlyName, root.Device.Manufacturer,
			method)
	}()

	// First, get all available clients from the device, and append to our
	// list of possible clients. Order matters here; we want to prefer
	// WANIPConnection2 over WANIPConnection1 or WANPPPConnection.
	wanIP2, _ := internetgateway2.NewWANIPConnection2ClientsFromRootDevice(ctx, root, loc)
	wanIP1, _ := internetgateway2.NewWANIPConnection1ClientsFromRootDevice(ctx, root, loc)
	wanPPP, _ := internetgateway2.NewWANPPPConnection1ClientsFromRootDevice(ctx, root, loc)

	var clients []upnpClient
	for _, v := range wanIP2 {
		clients = append(clients, v)
	}
	for _, v := range wanIP1 {
		clients = append(clients, v)
	}
	for _, v := range wanPPP {
		clients = append(clients, v)
	}

	// These are legacy services that were deprecated in 2015, but are
	// still in use by older devices; try them just in case.
	legacyClients, _ := goupnp.NewServiceClientsFromRootDevice(ctx, root, loc, urn_LegacyWANPPPConnection_1)
	metricUPnPSelectLegacy.Add(int64(len(legacyClients)))
	for _, client := range legacyClients {
		clients = append(clients, &legacyWANPPPConnection1{client})
	}
	legacyClients, _ = goupnp.NewServiceClientsFromRootDevice(ctx, root, loc, urn_LegacyWANIPConnection_1)
	metricUPnPSelectLegacy.Add(int64(len(legacyClients)))
	for _, client := range legacyClients {
		clients = append(clients, &legacyWANIPConnection1{client})
	}

	// If we have no clients, then return right now; if we only have one,
	// just select and return it.
	if len(clients) == 0 {
		return nil, nil
	}
	if len(clients) == 1 {
		method = "single"
		metricUPnPSelectSingle.Add(1)
		return clients[0], nil
	}

	metricUPnPSelectMultiple.Add(1)

	// In order to maximize the chances that we find a valid UPnP device
	// that can give us a port mapping, we check a few properties:
	//	1. Whether the device is "online", as defined by GetStatusInfo
	//	2. Whether the device has an external IP address, as defined by
	//	   GetExternalIPAddress
	//	3. Whether the device's external IP address is a public address
	//	   or a private one.
	//
	// We prefer a device where all of the above is true, and fall back if
	// none are found.
	//
	// In order to save on network requests, iterate through all devices
	// and determine how many "points" they have based on the above
	// criteria, but return immediately if we find one that meets all
	// three.
	var (
		connected   = make(map[upnpClient]bool)
		externalIPs map[upnpClient]netip.Addr
	)
	for _, svc := range clients {
		isConnected := serviceIsConnected(ctx, logf, svc)
		connected[svc] = isConnected

		// Don't bother checking for an external IP if the device isn't
		// connected; technically this could happen with a misbehaving
		// device, but that seems unlikely.
		if !isConnected {
			continue
		}

		// Check if the device has an external IP address.
		extIP, err := svc.GetExternalIPAddress(ctx)
		if err != nil {
			continue
		}
		externalIP, err := netip.ParseAddr(extIP)
		if err != nil {
			continue
		}
		mak.Set(&externalIPs, svc, externalIP)

		// If we get here, this device has a non-private external IP
		// and is up, so we can just return it.
		if !externalIP.IsPrivate() {
			method = "ext-public"
			metricUPnPSelectExternalPublic.Add(1)
			return svc, nil
		}
	}

	// Okay, we have no devices that meet all the available options. Fall
	// back to first checking for devices that are up and have a private
	// external IP (order matters), and then devices that are up, and then
	// just anything at all.
	//
	//	try=0	Up + private external IP
	//	try=1	Up
	for try := 0; try <= 1; try++ {
		for _, svc := range clients {
			if !connected[svc] {
				continue
			}
			_, hasExtIP := externalIPs[svc]
			if hasExtIP {
				method = "ext-private"
				metricUPnPSelectExternalPrivate.Add(1)
				return svc, nil
			} else if try == 1 {
				method = "up"
				metricUPnPSelectUp.Add(1)
				return svc, nil
			}
		}
	}

	// Nothing is up, but we have something (length of clients checked
	// above); just return the first one.
	metricUPnPSelectNone.Add(1)
	return clients[0], nil
}

// serviceIsConnected returns whether a given UPnP service is connected, based
// on the NewConnectionStatus field returned from GetStatusInfo.
func serviceIsConnected(ctx context.Context, logf logger.Logf, svc upnpClient) bool {
	status, _ /* NewLastConnectionError */, _ /* NewUptime */, err := svc.GetStatusInfo(ctx)
	if err != nil {
		return false
	}
	return status == "Connected" || status == "Up"
}

func (c *Client) upnpHTTPClientLocked() *http.Client {
	if c.uPnPHTTPClient == nil {
		c.uPnPHTTPClient = &http.Client{
			Transport: &http.Transport{
				DialContext:     netns.NewDialer(c.logf, c.netMon).DialContext,
				IdleConnTimeout: 2 * time.Second, // LAN is cheap
			},
		}
		if c.debug.LogHTTP {
			c.uPnPHTTPClient = requestLogger(c.logf, c.uPnPHTTPClient)
		}
	}
	return c.uPnPHTTPClient
}

var (
	disableUPnpEnv = envknob.RegisterBool("TS_DISABLE_UPNP")
)

// getUPnPPortMapping attempts to create a port-mapping over the UPnP protocol. On success,
// it will return the externally exposed IP and port. Otherwise, it will return a zeroed IP and
// port and an error.
func (c *Client) getUPnPPortMapping(
	ctx context.Context,
	gw netip.Addr,
	internal netip.AddrPort,
	prevPort uint16,
) (external netip.AddrPort, ok bool) {
	if disableUPnpEnv() || c.debug.DisableUPnP() {
		return netip.AddrPort{}, false
	}

	now := time.Now()
	upnp := &upnpMapping{
		gw:       gw,
		internal: internal,
	}

	// We can have multiple UPnP "meta" values (which correspond to the
	// UPnP discovery responses received). We want to try all of them when
	// obtaining a mapping, but also prefer any existing mapping's root
	// device (if present), since that will allow us to renew an existing
	// mapping instead of creating a new one.
	// Start by grabbing the list of metas, any existing mapping, and
	// creating a HTTP client for use.
	c.mu.Lock()
	oldMapping, ok := c.mapping.(*upnpMapping)
	metas := c.uPnPMetas
	ctx = goupnp.WithHTTPClient(ctx, c.upnpHTTPClientLocked())
	c.mu.Unlock()

	// Wrapper for a uPnPDiscoResponse with an optional existing root
	// device + URL (if we've got a previous cached mapping).
	type step struct {
		rootDev *goupnp.RootDevice // if nil, use 'meta'
		loc     *url.URL           // non-nil if rootDev is non-nil
		meta    uPnPDiscoResponse
	}
	var steps []step

	// Now, if we have an existing mapping, swap that mapping's entry to
	// the first entry in our "metas" list so we try it first.
	haveOldMapping := ok && oldMapping != nil
	if haveOldMapping && oldMapping.rootDev != nil {
		steps = append(steps, step{rootDev: oldMapping.rootDev, loc: oldMapping.loc})
	}
	// Note: this includes the meta for a previously-cached mapping, in
	// case the rootDev changes.
	for _, meta := range metas {
		steps = append(steps, step{meta: meta})
	}

	// Now, iterate through every meta that we have trying to get an
	// external IP address. If we succeed, we'll return; if we fail, we
	// continue this loop.
	var errs []error
	for _, step := range steps {
		var (
			rootDev *goupnp.RootDevice
			loc     *url.URL
			err     error
		)
		if step.rootDev != nil {
			rootDev = step.rootDev
			loc = step.loc
		} else {
			rootDev, loc, err = getUPnPRootDevice(ctx, c.logf, c.debug, gw, step.meta)
			c.vlogf("getUPnPRootDevice: loc=%q err=%v", loc, err)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if rootDev == nil {
			continue
		}

		// This actually performs the port mapping operation using this
		// root device.
		//
		// TODO(andrew-d): this can successfully perform a portmap and
		// return an externalAddrPort that refers to a non-public IP
		// address if the first selected RootDevice is a device that is
		// connected to another internal network. This is still better
		// than randomly flapping between multiple devices, but we
		// should probably split this up further to try the best
		// service (one with an external IP) first, instead of
		// iterating by device.
		//
		// This is probably sufficiently unlikely that I'm leaving that
		// as a follow-up task if it's necessary.
		externalAddrPort, client, err := c.tryUPnPPortmapWithDevice(ctx, internal, prevPort, rootDev, loc)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// If we get here, we're successful; we can cache this mapping,
		// update our local port, and then return.
		//
		// NOTE: this time might not technically be accurate if we created a
		// permanent lease above, but we should still re-check the presence of
		// the lease on a regular basis so we use it anyway.
		d := time.Duration(pmpMapLifetimeSec) * time.Second
		upnp.goodUntil = now.Add(d)
		upnp.renewAfter = now.Add(d / 2)
		upnp.external = externalAddrPort
		upnp.rootDev = rootDev
		upnp.loc = loc
		upnp.client = client

		c.mu.Lock()
		defer c.mu.Unlock()
		c.mapping = upnp
		c.localPort = externalAddrPort.Port()
		return upnp.external, true
	}

	// If we get here, we didn't get anything.
	// TODO(andrew-d): use or log errs?
	_ = errs
	return netip.AddrPort{}, false
}

// tryUPnPPortmapWithDevice attempts to perform a port forward from the given
// UPnP device to the 'internal' address. It tries to re-use the previous port,
// if a non-zero value is provided, and handles retries and errors about
// unsupported features.
//
// It returns the external address and port that was mapped (i.e. the
// address+port that another Tailscale node can use to make a connection to
// this one) and the UPnP client that was used to obtain that mapping.
func (c *Client) tryUPnPPortmapWithDevice(
	ctx context.Context,
	internal netip.AddrPort,
	prevPort uint16,
	rootDev *goupnp.RootDevice,
	loc *url.URL,
) (netip.AddrPort, upnpClient, error) {
	// Select the best mapping service from the given root device. This
	// makes network requests, and can vary from mapping to mapping if the
	// upstream device's connection status changes.
	client, err := selectBestService(ctx, c.logf, rootDev, loc)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}

	// If we have no client, we cannot continue; this can happen if we get
	// a valid UPnP response that does not contain any of the service types
	// that we know how to use.
	if client == nil {
		// For debugging, print all available services that we aren't
		// using because they're not supported; use c.vlogf so we don't
		// spam the logs unless verbose debugging is turned on.
		rootDev.Device.VisitServices(func(s *goupnp.Service) {
			c.vlogf("unsupported UPnP service: Type=%q ID=%q ControlURL=%q", s.ServiceType, s.ServiceId, s.ControlURL.Str)
		})

		return netip.AddrPort{}, nil, fmt.Errorf("no supported UPnP clients")
	}

	// Start by trying to make a temporary lease with a duration.
	var newPort uint16
	newPort, err = addAnyPortMapping(
		ctx,
		client,
		prevPort,
		internal.Port(),
		internal.Addr().String(),
		pmpMapLifetimeSec*time.Second,
	)
	c.vlogf("addAnyPortMapping: %v, err=%q", newPort, err)

	// If this is an error and the code is
	// "OnlyPermanentLeasesSupported", then we retry with no lease
	// duration; see the following issue for details:
	//    https://github.com/tailscale/tailscale/issues/9343
	if err != nil {
		code, ok := getUPnPErrorCode(err)
		if ok {
			getUPnPErrorsMetric(code).Add(1)
		}

		// From the UPnP spec: http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf
		//     402: Invalid Args (see: https://github.com/tailscale/tailscale/issues/15223)
		//     725: OnlyPermanentLeasesSupported
		if ok && (code == 402 || code == 725) {
			newPort, err = addAnyPortMapping(
				ctx,
				client,
				prevPort,
				internal.Port(),
				internal.Addr().String(),
				0, // permanent
			)
			c.vlogf("addAnyPortMapping: errcode=%d retried: port=%v err=%v", code, newPort, err)
		}
	}
	if err != nil {
		return netip.AddrPort{}, nil, err
	}

	// TODO cache this ip somewhere?
	extIP, err := client.GetExternalIPAddress(ctx)
	c.vlogf("client.GetExternalIPAddress: %v, %v", extIP, err)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	externalIP, err := netip.ParseAddr(extIP)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}

	// Do a bit of validation on the external IP; we've seen cases where
	// UPnP devices return the public IP 0.0.0.0, which obviously doesn't
	// work as an endpoint.
	//
	// See: https://github.com/tailscale/corp/issues/23538
	if externalIP.IsUnspecified() {
		c.logf("UPnP returned unspecified external IP %v", externalIP)
		return netip.AddrPort{}, nil, fmt.Errorf("UPnP returned unspecified external IP")
	} else if externalIP.IsLoopback() {
		c.logf("UPnP returned loopback external IP %v", externalIP)
		return netip.AddrPort{}, nil, fmt.Errorf("UPnP returned loopback external IP")
	}

	return netip.AddrPortFrom(externalIP, newPort), client, nil
}

// processUPnPResponses sorts and deduplicates a list of UPnP discovery
// responses, returning the possibly-reduced list.
//
// It will perform a consistent sort of the provided responses, so if we have
// multiple valid UPnP destinations a consistent option will be picked every
// time.
func processUPnPResponses(metas []uPnPDiscoResponse) []uPnPDiscoResponse {
	// Sort and compact all responses to remove duplicates; since
	// we send multiple probes, we often get duplicate responses.
	slices.SortFunc(metas, func(a, b uPnPDiscoResponse) int {
		// Sort the USN in reverse, so that
		// "InternetGatewayDevice:2" sorts before
		// "InternetGatewayDevice:1".
		if ii := cmp.Compare(a.USN, b.USN); ii != 0 {
			return -ii
		}
		if ii := cmp.Compare(a.Location, b.Location); ii != 0 {
			return ii
		}
		return cmp.Compare(a.Server, b.Server)
	})

	// We can get multiple responses that point to a single Location, since
	// we probe for both ssdp:all and InternetGatewayDevice:1 as
	// independent packets. Compact by comparing the Location and Server,
	// but not the USN (which contains the device being offered).
	//
	// Since the slices are sorted in reverse above, this means that if we
	// get a discovery response for both InternetGatewayDevice:1 and
	// InternetGatewayDevice:2, we'll keep the first
	// (InternetGatewayDevice:2) response, which is what we want.
	metas = slices.CompactFunc(metas, func(a, b uPnPDiscoResponse) bool {
		return a.Location == b.Location && a.Server == b.Server
	})

	return metas
}

// getUPnPErrorCode returns the UPnP error code from the given response, if the
// error is a SOAP error in the proper format, and a boolean indicating whether
// the provided error was actually a UPnP error.
func getUPnPErrorCode(err error) (int, bool) {
	soapErr, ok := err.(*soap.SOAPFaultError)
	if !ok {
		return 0, false
	}

	var upnpErr struct {
		XMLName     xml.Name
		Code        int    `xml:"errorCode"`
		Description string `xml:"errorDescription"`
	}
	if err := xml.Unmarshal([]byte(soapErr.Detail.Raw), &upnpErr); err != nil {
		return 0, false
	}
	if upnpErr.XMLName.Local != "UPnPError" {
		return 0, false
	}
	return upnpErr.Code, true
}

type uPnPDiscoResponse struct {
	Location string
	// Server describes what version the UPnP is, such as MiniUPnPd/2.x.x
	Server string
	// USN is the serial number of the device, which also contains
	// what kind of UPnP service is being offered, i.e. InternetGatewayDevice:2
	USN string
}

// parseUPnPDiscoResponse parses a UPnP HTTP-over-UDP discovery response.
func parseUPnPDiscoResponse(body []byte) (uPnPDiscoResponse, error) {
	var r uPnPDiscoResponse
	res, err := http.ReadResponse(bufio.NewReaderSize(bytes.NewReader(body), 128), nil)
	if err != nil {
		return r, err
	}
	r.Location = res.Header.Get("Location")
	r.Server = res.Header.Get("Server")
	r.USN = res.Header.Get("Usn")
	return r, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (r roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return r(req)
}

func requestLogger(logf logger.Logf, client *http.Client) *http.Client {
	// Clone the HTTP client, and override the Transport to log to the
	// provided logger.
	ret := *client
	oldTransport := ret.Transport

	var requestCounter atomic.Uint64
	loggingTransport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		ctr := requestCounter.Add(1)

		// Read the body and re-set it.
		var (
			body []byte
			err  error
		)
		if req.Body != nil {
			body, err = io.ReadAll(req.Body)
			req.Body.Close()
			if err != nil {
				return nil, err
			}
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		logf("request[%d]: %s %q body=%q", ctr, req.Method, req.URL, body)

		resp, err := oldTransport.RoundTrip(req)
		if err != nil {
			logf("response[%d]: err=%v", ctr, err)
			return nil, err
		}

		// Read the response body
		if resp.Body != nil {
			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				logf("response[%d]: %d bodyErr=%v", ctr, resp.StatusCode, err)
				return nil, err
			}
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}

		logf("response[%d]: %d body=%q", ctr, resp.StatusCode, body)
		return resp, nil
	})
	ret.Transport = loggingTransport

	return &ret
}
