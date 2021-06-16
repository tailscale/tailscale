// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package portmapper

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"
	"inet.af/netaddr"
	"tailscale.com/tempfork/upnp/dcps/internetgateway2"
)

type upnpMapping struct {
	gw       netaddr.IP
	external netaddr.IPPort
	internal netaddr.IPPort
	useUntil time.Time
	client   upnpClient
}

func (u *upnpMapping) isCurrent() bool                { return u.useUntil.After(time.Now()) }
func (u *upnpMapping) validUntil() time.Time          { return u.useUntil }
func (u *upnpMapping) externalIPPort() netaddr.IPPort { return u.external }
func (u *upnpMapping) release() {
	u.client.DeletePortMapping(context.Background(), "", u.external.Port(), "udp")
}

type upnpClient interface {
	// http://upnp.org/specs/gw/UPnP-gw-WANIPConnection-v2-Service.pdf
	// Implicitly assume that the calls for all these are uniform, which might be a dangerous
	// assumption.
	AddPortMapping(
		ctx context.Context,
		newRemoteHost string,
		newExternalPort uint16,
		newProtocol string,
		newInternalPort uint16,
		newInternalClient string,
		newEnabled bool,
		newPortMappingDescription string,
		newLeaseDuration uint32,
	) (err error)

	DeletePortMapping(ctx context.Context, newRemoteHost string, newExternalPort uint16, newProtocol string) error
	GetStatusInfo(ctx context.Context) (status string, lastErr string, uptime uint32, err error)
	GetExternalIPAddress(ctx context.Context) (externalIPAddress string, err error)

	RequestTermination(ctx context.Context) error
	RequestConnection(ctx context.Context) error
}

// addAnyPortMapping abstracts over different UPnP client connections, calling the available
// AddAnyPortMapping call if available, otherwise defaulting to the old behavior of calling
// AddPortMapping with port = 0 to specify a wildcard port.
func addAnyPortMapping(
	ctx context.Context,
	upnp upnpClient,
	newRemoteHost string,
	newExternalPort uint16,
	newProtocol string,
	newInternalPort uint16,
	newInternalClient string,
	newEnabled bool,
	newPortMappingDescription string,
	newLeaseDuration uint32,
) (newPort uint16, err error) {
	if upnp, ok := upnp.(*internetgateway2.WANIPConnection2); ok {
		return upnp.AddAnyPortMapping(
			ctx,
			newRemoteHost,
			newExternalPort,
			newProtocol,
			newInternalPort,
			newInternalClient,
			newEnabled,
			newPortMappingDescription,
			newLeaseDuration,
		)
	}
	err = upnp.AddPortMapping(
		ctx,
		newRemoteHost,
		newExternalPort,
		newProtocol,
		newInternalPort,
		newInternalClient,
		newEnabled,
		newPortMappingDescription,
		newLeaseDuration,
	)
	return newInternalPort, err
}

// getUPnPClients gets a client for interfacing with UPnP, ignoring the underlying protocol for
// now.
// Adapted from https://github.com/huin/goupnp/blob/master/GUIDE.md.
func getUPnPClient(ctx context.Context) (upnpClient, error) {
	tasks, _ := errgroup.WithContext(ctx)
	// Attempt to connect over the multiple available connection types.
	var ip1Clients []*internetgateway2.WANIPConnection1
	tasks.Go(func() error {
		var err error
		ip1Clients, _, err = internetgateway2.NewWANIPConnection1Clients()
		return err
	})
	var ip2Clients []*internetgateway2.WANIPConnection2
	tasks.Go(func() error {
		var err error
		ip2Clients, _, err = internetgateway2.NewWANIPConnection2Clients()
		return err
	})
	var ppp1Clients []*internetgateway2.WANPPPConnection1
	tasks.Go(func() error {
		var err error
		ppp1Clients, _, err = internetgateway2.NewWANPPPConnection1Clients()
		return err
	})

	err := tasks.Wait()

	switch {
	case len(ip2Clients) > 0:
		return ip2Clients[0], nil
	case len(ip1Clients) > 0:
		return ip1Clients[0], nil
	case len(ppp1Clients) > 0:
		return ppp1Clients[0], nil
	default:
		// Didn't get any outputs, report if there was an error or nil if
		// just no clients.
		return nil, err
	}
}

// getUPnPPortMapping will attempt to create a port-mapping over the UPnP protocol. On success,
// it will return the externally exposed IP and port. Otherwise, it will return a zeroed IP and
// port and an error.
func (c *Client) getUPnPPortMapping(ctx context.Context, gw netaddr.IP, internal netaddr.IPPort,
	prevPort uint16) (external netaddr.IPPort, err error) {
	// If did not see UPnP within the past 5 seconds then bail
	haveRecentUPnP := c.sawUPnPRecently()
	now := time.Now()
	if c.lastProbe.After(now.Add(-5*time.Second)) && !haveRecentUPnP {
		return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
	}
	// Otherwise try a uPnP mapping if PMP did not work
	mpnp := &upnpMapping{
		gw:       gw,
		internal: internal,
	}

	var client upnpClient
	c.mu.Lock()
	oldMapping, ok := c.mapping.(*upnpMapping)
	c.mu.Unlock()
	if ok && oldMapping != nil {
		client = oldMapping.client
	} else if c.Prober != nil && c.Prober.upnpClient != nil {
		client = c.Prober.upnpClient
	} else {
		client, err = getUPnPClient(ctx)
		if err != nil {
			return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
		}
	}
	if client == nil {
		return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
	}

	var newPort uint16
	newPort, err = addAnyPortMapping(
		ctx, client,
		"", prevPort, "UDP", internal.Port(), internal.IP().String(), true,
		// string below is just a name for reporting on device.
		"tailscale-portmap", pmpMapLifetimeSec,
	)
	if err != nil {
		return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
	}
	// TODO cache this ip somewhere?
	extIP, err := client.GetExternalIPAddress(ctx)
	if err != nil {
		// TODO this doesn't seem right
		return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
	}
	externalIP, err := netaddr.ParseIP(extIP)
	if err != nil {
		return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
	}

	mpnp.external = netaddr.IPPortFrom(externalIP, newPort)
	d := time.Duration(pmpMapLifetimeSec) * time.Second / 2
	mpnp.useUntil = time.Now().Add(d)
	mpnp.client = client
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mapping = mpnp
	c.localPort = newPort
	return mpnp.external, nil
}
