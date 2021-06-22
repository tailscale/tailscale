// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/tailscale/goupnp/dcps/internetgateway2"
	"inet.af/netaddr"
	"tailscale.com/control/controlknobs"
)

// References:
//
// WANIP Connection v2: http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf

// upnpMapping is a port mapping over the upnp protocol. After being created it is immutable,
// but the client field may be shared across mapping instances.
type upnpMapping struct {
	gw         netaddr.IP
	external   netaddr.IPPort
	internal   netaddr.IPPort
	goodUntil  time.Time
	renewAfter time.Time

	// client is a connection to a upnp device, and may be reused across different UPnP mappings.
	client upnpClient
}

func (u *upnpMapping) GoodUntil() time.Time     { return u.goodUntil }
func (u *upnpMapping) RenewAfter() time.Time    { return u.renewAfter }
func (u *upnpMapping) External() netaddr.IPPort { return u.external }
func (u *upnpMapping) Release(ctx context.Context) {
	u.client.DeletePortMapping(ctx, "", u.external.Port(), "udp")
}

// upnpClient is an interface over the multiple different clients exported by goupnp,
// exposing the functions we need for portmapping. They are auto-generated from XML-specs.
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
	) (err error)

	DeletePortMapping(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
	GetExternalIPAddress(ctx context.Context) (externalIPAddress string, err error)
}

// tsPortMappingDesc gets sent to UPnP clients as a human-readable label for the portmapping.
// It is not used for anything other than labelling.
const tsPortMappingDesc = "tailscale-portmap"

// addAnyPortMapping abstracts over different UPnP client connections, calling the available
// AddAnyPortMapping call if available for WAN IP connection v2, otherwise defaulting to the old
// behavior of calling AddPortMapping with port = 0 to specify a wildcard port.
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
	return internalPort, err
}

// getUPnPClients gets a client for interfacing with UPnP, ignoring the underlying protocol for
// now.
// Adapted from https://github.com/huin/goupnp/blob/master/GUIDE.md.
func getUPnPClient(ctx context.Context, gw netaddr.IP) (upnpClient, error) {
	if dis, ok := controlknobs.DisableUPnP().Get(); ok && dis {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	// Attempt to connect over the multiple available connection types concurrently,
	// returning the fastest.

	// TODO(jknodt): this url seems super brittle? maybe discovery is better but this is faster
	u, err := url.Parse(fmt.Sprintf("http://%s:5000/rootDesc.xml", gw))
	if err != nil {
		return nil, err
	}

	clients := make(chan upnpClient, 3)
	go func() {
		var err error
		ip1Clients, err := internetgateway2.NewWANIPConnection1ClientsByURL(ctx, u)
		if err == nil && len(ip1Clients) > 0 {
			clients <- ip1Clients[0]
		}
	}()
	go func() {
		ip2Clients, err := internetgateway2.NewWANIPConnection2ClientsByURL(ctx, u)
		if err == nil && len(ip2Clients) > 0 {
			clients <- ip2Clients[0]
		}
	}()
	go func() {
		ppp1Clients, err := internetgateway2.NewWANPPPConnection1ClientsByURL(ctx, u)
		if err == nil && len(ppp1Clients) > 0 {
			clients <- ppp1Clients[0]
		}
	}()

	select {
	case client := <-clients:
		return client, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// getUPnPPortMapping attempts to create a port-mapping over the UPnP protocol. On success,
// it will return the externally exposed IP and port. Otherwise, it will return a zeroed IP and
// port and an error.
func (c *Client) getUPnPPortMapping(
	ctx context.Context,
	gw netaddr.IP,
	internal netaddr.IPPort,
	prevPort uint16,
) (external netaddr.IPPort, ok bool) {
	if dis, ok := controlknobs.DisableUPnP().Get(); ok && dis {
		return netaddr.IPPort{}, false
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
	c.mu.Unlock()
	if ok && oldMapping != nil {
		client = oldMapping.client
	} else {
		client, err = getUPnPClient(ctx, gw)
		if err != nil {
			return netaddr.IPPort{}, false
		}
	}
	if client == nil {
		return netaddr.IPPort{}, false
	}

	var newPort uint16
	newPort, err = addAnyPortMapping(
		ctx,
		client,
		prevPort,
		internal.Port(),
		internal.IP().String(),
		time.Second*pmpMapLifetimeSec,
	)
	if err != nil {
		return netaddr.IPPort{}, false
	}
	// TODO cache this ip somewhere?
	extIP, err := client.GetExternalIPAddress(ctx)
	if err != nil {
		// TODO this doesn't seem right
		return netaddr.IPPort{}, false
	}
	externalIP, err := netaddr.ParseIP(extIP)
	if err != nil {
		return netaddr.IPPort{}, false
	}

	upnp.external = netaddr.IPPortFrom(externalIP, newPort)
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
