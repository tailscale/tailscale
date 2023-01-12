// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !js

// (no raw sockets in JS/WASM)

package portmapper

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/tailscale/goupnp"
	"github.com/tailscale/goupnp/dcps/internetgateway2"
	"tailscale.com/control/controlknobs"
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

func (u *upnpMapping) GoodUntil() time.Time     { return u.goodUntil }
func (u *upnpMapping) RenewAfter() time.Time    { return u.renewAfter }
func (u *upnpMapping) External() netip.AddrPort { return u.external }
func (u *upnpMapping) Release(ctx context.Context) {
	u.client.DeletePortMapping(ctx, "", u.external.Port(), "udp")
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

		// protocol is whether this is over TCP or UDP. Either "tcp" or "udp".
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

// addAnyPortMapping abstracts over different UPnP client connections, calling the available
// AddAnyPortMapping call if available for WAN IP connection v2, otherwise defaulting to the old
// behavior of calling AddPortMapping with port = 0 to specify a wildcard port.
// It returns the new external port (which may not be identical to the external port specified),
// or an error.
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
	if upnp, ok := upnp.(*internetgateway2.WANIPConnection2); ok {
		return upnp.AddAnyPortMapping(
			ctx,
			"",
			externalPort,
			"udp",
			internalPort,
			internalClient,
			true,
			tsPortMappingDesc,
			uint32(leaseDuration.Seconds()),
		)
	}
	for externalPort == 0 {
		externalPort = uint16(rand.Intn(65535))
	}
	err = upnp.AddPortMapping(
		ctx,
		"",
		externalPort,
		"udp",
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
func getUPnPClient(ctx context.Context, logf logger.Logf, gw netip.Addr, meta uPnPDiscoResponse) (client upnpClient, err error) {
	if controlknobs.DisableUPnP() || DisableUPnP {
		return nil, nil
	}

	if meta.Location == "" {
		return nil, nil
	}

	if VerboseLogs {
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
				DialContext:     netns.NewDialer(c.logf).DialContext,
				IdleConnTimeout: 2 * time.Second, // LAN is cheap
			},
		}
	}
	return c.uPnPHTTPClient
}

// getUPnPPortMapping attempts to create a port-mapping over the UPnP protocol. On success,
// it will return the externally exposed IP and port. Otherwise, it will return a zeroed IP and
// port and an error.
func (c *Client) getUPnPPortMapping(
	ctx context.Context,
	gw netip.Addr,
	internal netip.AddrPort,
	prevPort uint16,
) (external netip.AddrPort, ok bool) {
	if controlknobs.DisableUPnP() || DisableUPnP {
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
		client, err = getUPnPClient(ctx, c.logf, gw, meta)
		if VerboseLogs {
			c.logf("getUPnPClient: %T, %v", client, err)
		}
		if err != nil {
			return netip.AddrPort{}, false
		}
	}
	if client == nil {
		return netip.AddrPort{}, false
	}

	var newPort uint16
	newPort, err = addAnyPortMapping(
		ctx,
		client,
		prevPort,
		internal.Port(),
		internal.Addr().String(),
		time.Second*pmpMapLifetimeSec,
	)
	if VerboseLogs {
		c.logf("addAnyPortMapping: %v, %v", newPort, err)
	}
	if err != nil {
		return netip.AddrPort{}, false
	}
	// TODO cache this ip somewhere?
	extIP, err := client.GetExternalIPAddress(ctx)
	if VerboseLogs {
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
