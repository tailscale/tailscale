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

	DeletePortMapping(ctx context.Context, NewRemoteHost string, NewExternalPort uint16, NewProtocol string) error
	GetStatusInfo(ctx context.Context) (status string, lastErr string, uptime uint32, err error)

	RequestTermination(ctx context.Context) error
	RequestConnection(ctx context.Context) error
}

func AddAnyPortMapping(
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
