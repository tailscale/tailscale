// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js

// (no raw sockets in JS/WASM)

package portmapper

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tailscale/goupnp"
	"github.com/tailscale/goupnp/dcps/internetgateway2"
	"github.com/tailscale/goupnp/soap"
	"tailscale.com/envknob"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
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

	// client is a connection to a upnp device, and may be reused across different UPnP mappings.
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

func (u *upnpMapping) GoodUntil() time.Time     { return u.goodUntil }
func (u *upnpMapping) RenewAfter() time.Time    { return u.renewAfter }
func (u *upnpMapping) External() netip.AddrPort { return u.external }
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
		externalPort = uint16(rand.Intn(65535-1024) + 1024)
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

// getUPnPClient gets a client for interfacing with UPnP, ignoring the underlying protocol for
// now.
// Adapted from https://github.com/huin/goupnp/blob/master/GUIDE.md.
//
// The gw is the detected gateway.
//
// The meta is the most recently parsed UDP discovery packet response
// from the Internet Gateway Device.
//
// The provided ctx is not retained in the returned upnpClient, but
// its associated HTTP client is (if set via goupnp.WithHTTPClient).
func getUPnPClient(ctx context.Context, logf logger.Logf, debug DebugKnobs, gw netip.Addr, meta uPnPDiscoResponse) (client upnpClient, err error) {
	if debug.DisableUPnP {
		return nil, nil
	}

	if meta.Location == "" {
		return nil, nil
	}

	if debug.VerboseLogs {
		logf("fetching %v", meta.Location)
	}
	u, err := url.Parse(meta.Location)
	if err != nil {
		return nil, err
	}

	ipp, err := netip.ParseAddrPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("unexpected host %q in %q", u.Host, meta.Location)
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
		return nil, err
	}

	defer func() {
		if client == nil {
			return
		}
		logf("saw UPnP type %v at %v; %v (%v)",
			strings.TrimPrefix(fmt.Sprintf("%T", client), "*internetgateway2."),
			meta.Location, root.Device.FriendlyName, root.Device.Manufacturer)
	}()

	// These parts don't do a network fetch.
	// Pick the best service type available.
	if cc, _ := internetgateway2.NewWANIPConnection2ClientsFromRootDevice(ctx, root, u); len(cc) > 0 {
		return cc[0], nil
	}
	if cc, _ := internetgateway2.NewWANIPConnection1ClientsFromRootDevice(ctx, root, u); len(cc) > 0 {
		return cc[0], nil
	}
	if cc, _ := internetgateway2.NewWANPPPConnection1ClientsFromRootDevice(ctx, root, u); len(cc) > 0 {
		return cc[0], nil
	}
	return nil, nil
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
	if disableUPnpEnv() || c.debug.DisableUPnP || (c.controlKnobs != nil && c.controlKnobs.DisableUPnP.Load()) {
		return netip.AddrPort{}, false
	}

	now := time.Now()
	upnp := &upnpMapping{
		gw:       gw,
		internal: internal,
	}

	var client upnpClient
	var err error
	c.mu.Lock()
	oldMapping, ok := c.mapping.(*upnpMapping)
	meta := c.uPnPMeta
	httpClient := c.upnpHTTPClientLocked()
	c.mu.Unlock()
	if ok && oldMapping != nil {
		client = oldMapping.client
	} else {
		ctx := goupnp.WithHTTPClient(ctx, httpClient)
		client, err = getUPnPClient(ctx, c.logf, c.debug, gw, meta)
		if c.debug.VerboseLogs {
			c.logf("getUPnPClient: %T, %v", client, err)
		}
		if err != nil {
			return netip.AddrPort{}, false
		}
	}
	if client == nil {
		return netip.AddrPort{}, false
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
	if c.debug.VerboseLogs {
		c.logf("addAnyPortMapping: %v, err=%q", newPort, err)
	}

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
		//     725: OnlyPermanentLeasesSupported
		if ok && code == 725 {
			newPort, err = addAnyPortMapping(
				ctx,
				client,
				prevPort,
				internal.Port(),
				internal.Addr().String(),
				0, // permanent
			)
			if c.debug.VerboseLogs {
				c.logf("addAnyPortMapping: 725 retry %v, err=%q", newPort, err)
			}
		}
	}
	if err != nil {
		return netip.AddrPort{}, false
	}

	// TODO cache this ip somewhere?
	extIP, err := client.GetExternalIPAddress(ctx)
	if c.debug.VerboseLogs {
		c.logf("client.GetExternalIPAddress: %v, %v", extIP, err)
	}
	if err != nil {
		// TODO this doesn't seem right
		return netip.AddrPort{}, false
	}
	externalIP, err := netip.ParseAddr(extIP)
	if err != nil {
		return netip.AddrPort{}, false
	}

	upnp.external = netip.AddrPortFrom(externalIP, newPort)

	// NOTE: this time might not technically be accurate if we created a
	// permanent lease above, but we should still re-check the presence of
	// the lease on a regular basis so we use it anyway.
	d := time.Duration(pmpMapLifetimeSec) * time.Second
	upnp.goodUntil = now.Add(d)
	upnp.renewAfter = now.Add(d / 2)
	upnp.client = client
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mapping = upnp
	c.localPort = newPort
	return upnp.external, true
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
			logf("response[%d]: err=%v", err)
			return nil, err
		}

		// Read the response body
		if resp.Body != nil {
			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				logf("response[%d]: %d bodyErr=%v", resp.StatusCode, err)
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
